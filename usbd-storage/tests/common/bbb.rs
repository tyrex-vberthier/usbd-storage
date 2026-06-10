#[cfg(feature = "transfer")]
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use usb_device::bus::{PollResult, UsbBus};
use usb_device::class_prelude::{EndpointAddress, EndpointType};
use usb_device::{UsbDirection, UsbError};

#[cfg(feature = "transfer")]
use usbd_storage::transfer::TransferBus;

const MAX_CB_LEN: u8 = 16;
const CSW_LEN: u8 = 13;

#[derive(Debug, Eq, PartialEq)]
pub enum CommandStatus {
    Passed = 0x00,
    Failed = 0x01,
    PhaseError = 0x02,
}

#[allow(dead_code)]
pub enum DataDirection {
    Out,
    In,
    NotExpected,
}
pub struct Cbw {
    pub(crate) data_transfer_len: u32,
    pub(crate) direction: DataDirection,
    pub(crate) block: Vec<u8>,
}

impl Cbw {
    pub fn into_bytes(self) -> Vec<u8> {
        const CBW_SIGNATURE_LE: [u8; 4] = 0x43425355u32.to_le_bytes();

        assert!((1..=16).contains(&self.block.len()));

        let mut bytes = vec![];
        bytes.extend_from_slice(CBW_SIGNATURE_LE.as_slice()); // signature
        bytes.extend_from_slice([0u8; 4].as_slice()); //tag
        bytes.extend_from_slice(self.data_transfer_len.to_le_bytes().as_slice()); // data transfer len

        let direction = match self.direction {
            DataDirection::In => 1_u8 << 7,
            DataDirection::Out | DataDirection::NotExpected => 0u8,
        };
        bytes.push(direction); // direction
        bytes.push(0); // lun
        bytes.push(self.block.len() as u8); // block size

        let mut block = vec![0u8; MAX_CB_LEN as usize];
        block.as_mut_slice()[..self.block.len()].copy_from_slice(self.block.as_slice());
        bytes.extend_from_slice(block.as_slice()); // block

        bytes
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Csw {
    pub(crate) data_transfer_len: u32,
    pub(crate) status: CommandStatus,
}

impl Csw {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(CSW_LEN as usize, bytes.len());

        let data_transfer_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let status = match bytes[12] {
            0x00 => CommandStatus::Passed,
            0x01 => CommandStatus::Failed,
            0x02 => CommandStatus::PhaseError,
            _ => panic!("invalid status code"),
        };

        Self {
            data_transfer_len,
            status,
        }
    }
}

pub struct DummyEp {
    addr: EndpointAddress,
    max_packet_size: u16,
    stalled: bool,
    bytes_written: usize,
    bytes_read: usize,
    packets: VecDeque<Vec<u8>>,
}

impl DummyEp {
    pub fn new(addr: EndpointAddress, max_packet_size: u16) -> Self {
        Self {
            addr,
            max_packet_size,
            stalled: false,
            bytes_written: 0,
            bytes_read: 0,
            packets: VecDeque::new(),
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(self.max_packet_size as usize) {
            self.packets.push_back(chunk.to_vec());
        }
        self.bytes_written += bytes.len();
    }

    pub fn read_packet(&mut self) -> Option<Vec<u8>> {
        let packet = self.packets.pop_front();
        if let Some(len) = packet.as_ref().map(|p| p.len()) {
            self.bytes_read += len;
        }
        packet
    }
}

#[derive(Eq, PartialEq)]
pub struct BytesProcessed {
    /// (written, read)
    ep_in: (usize, usize),
    /// (written, read)
    ep_out: (usize, usize),
}

// ---------------------------------------------------------------------------
// TransferBus support types (feature = "transfer")
// ---------------------------------------------------------------------------

/// A single pending transfer record submitted to the mock TransferBus.
///
/// IN transfers (submit_write) store a copy of the bytes so they can be
/// retrieved by the test via `complete_in_transfer`.
///
/// OUT transfers (submit_read) store the raw pointer handed to `submit_read`.
/// **Safety**: the test body must keep the original `&mut [u8]` slice alive
/// and must not access it until `poll_transfer` retires this record. This is
/// test-only; production firmware fulfills the same contract via the DMA
/// buffer-validity rule in [`TransferBus`].
#[cfg(feature = "transfer")]
struct PendingTransfer {
    /// The raw OUT buffer pointer + length for host→device transfers, or
    /// `None` for device→host (IN) transfers where we store the bytes inline.
    out_buf: Option<(*mut u8, usize)>,
    /// Bytes captured for IN transfers on submit, or the data copied in by
    /// `complete_out_transfer`.
    data: Vec<u8>,
    /// `true` once the test calls `complete_*_transfer` to retire this entry.
    complete: bool,
    /// The byte count the driver will see from `poll_transfer`.
    completed_len: usize,
}

// SAFETY: raw pointers are test-only. Test bodies hold the buffer alive and
// do not access it between submit and retire. No concurrent access.
#[cfg(feature = "transfer")]
unsafe impl Send for PendingTransfer {}
#[cfg(feature = "transfer")]
unsafe impl Sync for PendingTransfer {}

/// Per-endpoint FIFO queue of pending transfers.
#[cfg(feature = "transfer")]
struct TransferQueue {
    queue: VecDeque<PendingTransfer>,
    /// Total number of `submit_read` calls — used by the no-swallow assertion.
    submit_read_count: usize,
    /// Sizes of each `submit_read` call, in order.
    submit_read_lens: Vec<usize>,
}

#[cfg(feature = "transfer")]
impl TransferQueue {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            submit_read_count: 0,
            submit_read_lens: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct DummyUsbBus {
    inner: Arc<Mutex<Inner>>,
}

impl DummyUsbBus {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new())),
        }
    }

    /// Write Command Block Wrapper as if it was written by a USB host
    pub fn write_cbw(&self, cbw: Cbw) {
        let mut lock = self.inner.lock().unwrap();
        let ep = lock.ep_out.as_mut().unwrap();
        ep.write_bytes(cbw.into_bytes().as_slice());
    }

    /// Read Command Status as if it was read by a USB host
    pub fn read_cs(&self) -> Option<Csw> {
        let mut bytes = vec![];
        while bytes.len() < CSW_LEN as usize {
            let mut packet = self.read_packet()?;
            bytes.append(&mut packet);
        }
        Some(Csw::from_bytes(bytes.as_slice()))
    }

    /// Write some data as if it was written by a USB host during Host to Device data transfer
    pub fn write_data(&self, data: &[u8]) {
        let mut lock = self.inner.lock().unwrap();
        let ep = lock.ep_out.as_mut().unwrap();
        ep.write_bytes(data);
    }

    /// Read a single packet as if it was read by a USB host during Device to Host data transfer
    pub fn read_packet(&self) -> Option<Vec<u8>> {
        let mut lock = self.inner.lock().unwrap();
        let ep = lock.ep_in.as_mut().unwrap();
        ep.read_packet()
    }

    pub fn read_n_bytes(&self, n: usize) -> Vec<u8> {
        let mut lock = self.inner.lock().unwrap();
        let ep = lock.ep_in.as_mut().unwrap();

        assert_eq!(0, n % ep.max_packet_size as usize);

        let mut bytes = vec![];
        while bytes.len() < n {
            match ep.read_packet() {
                None => {
                    break;
                }
                Some(mut packet) => {
                    bytes.append(&mut packet);
                }
            }
        }

        bytes
    }

    pub fn bytes_processed(&self) -> BytesProcessed {
        let lock = self.inner.lock().unwrap();
        BytesProcessed {
            ep_in: (lock
                .ep_in
                .as_ref()
                .map(|ep| (ep.bytes_written, ep.bytes_read))
                .unwrap()),
            ep_out: (lock
                .ep_out
                .as_ref()
                .map(|ep| (ep.bytes_written, ep.bytes_read))
                .unwrap()),
        }
    }

    // -----------------------------------------------------------------------
    // TransferBus helpers (feature = "transfer")
    // -----------------------------------------------------------------------

    /// Simulate the host completing an OUT transfer: copy `data` into the head
    /// pending OUT buffer for `ep`, mark it complete with the actual byte count.
    ///
    /// Allows short completions: if `data.len() < submitted_len` only
    /// `data.len()` bytes are written and the completed length is `data.len()`.
    #[cfg(feature = "transfer")]
    pub fn complete_out_transfer(&self, ep: EndpointAddress, data: &[u8]) {
        let mut lock = self.inner.lock().unwrap();
        let queues = &mut lock.transfer_queues;
        let ep_key = u8::from(ep);
        let queue = queues.get_mut(&ep_key).expect("no transfer queue for ep");
        let entry = queue
            .queue
            .front_mut()
            .expect("no pending OUT transfer to complete");
        assert!(
            !entry.complete,
            "complete_out_transfer called on already-complete entry"
        );
        let (ptr, cap) = entry
            .out_buf
            .expect("complete_out_transfer called on an IN transfer");
        let copy_len = data.len().min(cap);
        // SAFETY: the test body keeps the original slice alive and does not
        // access it between submit_read and poll_transfer retiring the record.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, copy_len);
        }
        entry.completed_len = copy_len;
        entry.complete = true;
    }

    /// Simulate the host completing an IN transfer: snapshot the bytes that
    /// were submitted via `submit_write` for `ep`, mark it complete.
    ///
    /// Completes the oldest NOT-YET-complete IN transfer entry in FIFO order,
    /// skipping any already-complete entries (which are awaiting `poll_transfer`
    /// retirement by the firmware).  Returns the bytes for assertion.
    #[cfg(feature = "transfer")]
    pub fn complete_in_transfer(&self, ep: EndpointAddress) -> Vec<u8> {
        let mut lock = self.inner.lock().unwrap();
        let queues = &mut lock.transfer_queues;
        let ep_key = u8::from(ep);
        let queue = queues.get_mut(&ep_key).expect("no transfer queue for ep");
        let entry = queue
            .queue
            .iter_mut()
            .find(|e| !e.complete)
            .expect("no pending IN transfer to complete");
        let bytes = entry.data.clone();
        entry.completed_len = bytes.len();
        entry.complete = true;
        bytes
    }

    /// Return a snapshot of every `submit_read` length recorded for `ep`,
    /// in submission order.  Used for the no-swallow assertion.
    #[cfg(feature = "transfer")]
    pub fn submit_read_lens(&self, ep: EndpointAddress) -> Vec<usize> {
        let lock = self.inner.lock().unwrap();
        let ep_key = u8::from(ep);
        lock.transfer_queues
            .get(&ep_key)
            .map(|q| q.submit_read_lens.clone())
            .unwrap_or_default()
    }

    /// Address of the IN endpoint as allocated by the mock bus.
    #[cfg(feature = "transfer")]
    pub fn in_ep_addr(&self) -> EndpointAddress {
        let lock = self.inner.lock().unwrap();
        lock.ep_in.as_ref().unwrap().addr
    }

    /// Address of the OUT endpoint as allocated by the mock bus.
    #[cfg(feature = "transfer")]
    pub fn out_ep_addr(&self) -> EndpointAddress {
        let lock = self.inner.lock().unwrap();
        lock.ep_out.as_ref().unwrap().addr
    }

    /// Block the next `n` `UsbBus::write` calls (return WouldBlock).
    /// Used to simulate a depth-1 IN endpoint that is not yet ready.
    #[cfg(feature = "transfer")]
    pub fn block_next_writes(&self, n: usize) {
        self.inner.lock().unwrap().writes_to_block = n;
    }
}

struct Inner {
    enabled: bool,
    ep_in: Option<DummyEp>,
    ep_out: Option<DummyEp>,
    /// Per-endpoint transfer queues for the TransferBus impl.
    #[cfg(feature = "transfer")]
    transfer_queues: HashMap<u8, TransferQueue>,
    /// Number of `UsbBus::write` calls to return `WouldBlock` before
    /// succeeding.  Used by `csw_blocks_until_in_transfer_retires` to
    /// simulate a depth-1 IN endpoint that isn't ready yet.
    writes_to_block: usize,
}

impl Inner {
    fn new() -> Self {
        Self {
            enabled: false,
            ep_in: None,
            ep_out: None,
            #[cfg(feature = "transfer")]
            transfer_queues: HashMap::new(),
            writes_to_block: 0,
        }
    }
}

impl UsbBus for DummyUsbBus {
    fn alloc_ep(
        &mut self,
        ep_dir: UsbDirection,
        _ep_addr: Option<EndpointAddress>,
        ep_type: EndpointType,
        max_packet_size: u16,
        _interval: u8,
    ) -> usb_device::Result<EndpointAddress> {
        assert!(!self.inner.lock().unwrap().enabled);

        const EP_OUT_ADDR: usize = 0xFF;
        const EP_IN_ADDR: usize = 0xEE;
        const EP_CTRL: usize = 0;

        if matches!(ep_type, EndpointType::Control) {
            return Ok(EndpointAddress::from(EP_CTRL as u8));
        }

        let mut lock = self.inner.lock().unwrap();
        let addr = match ep_dir {
            UsbDirection::Out => {
                let addr = EndpointAddress::from(EP_OUT_ADDR as u8);
                lock.ep_out.replace(DummyEp::new(addr, max_packet_size));
                #[cfg(feature = "transfer")]
                lock.transfer_queues
                    .insert(EP_OUT_ADDR as u8, TransferQueue::new());
                addr
            }
            UsbDirection::In => {
                let addr = EndpointAddress::from(EP_IN_ADDR as u8);
                lock.ep_in.replace(DummyEp::new(addr, max_packet_size));
                #[cfg(feature = "transfer")]
                lock.transfer_queues
                    .insert(EP_IN_ADDR as u8, TransferQueue::new());
                addr
            }
        };

        Ok(addr)
    }

    fn enable(&mut self) {
        self.inner.lock().unwrap().enabled = true;
    }

    fn reset(&self) {}

    fn set_device_address(&self, _addr: u8) {}

    fn write(&self, ep_addr: EndpointAddress, buf: &[u8]) -> usb_device::Result<usize> {
        let mut lock = self.inner.lock().unwrap();

        // Honour the configurable write-block counter before touching the ep.
        if lock.writes_to_block > 0 {
            lock.writes_to_block -= 1;
            return Err(UsbError::WouldBlock);
        }

        let ep = lock.ep_in.as_mut().unwrap();

        if ep.addr != ep_addr {
            return Err(UsbError::InvalidEndpoint);
        }

        if buf.len() > ep.max_packet_size as usize {
            return Err(UsbError::BufferOverflow);
        }

        ep.write_bytes(buf);

        Ok(buf.len())
    }

    fn read(&self, ep_addr: EndpointAddress, buf: &mut [u8]) -> usb_device::Result<usize> {
        let mut lock = self.inner.lock().unwrap();
        let ep = lock.ep_out.as_mut().unwrap();

        if ep.addr != ep_addr {
            return Err(UsbError::InvalidEndpoint);
        }

        if let Some(n) = ep.packets.front().map(|p| p.len())
            && n > buf.len()
        {
            return Err(UsbError::BufferOverflow);
        }

        match ep.read_packet() {
            Some(packet) => {
                let n = packet.len();
                buf[..n].copy_from_slice(packet.as_slice());
                Ok(n)
            }
            None => Err(UsbError::WouldBlock),
        }
    }

    fn set_stalled(&self, ep_addr: EndpointAddress, stalled: bool) {
        let mut lock = self.inner.lock().unwrap();

        if let Some(ep) = lock.ep_in.as_mut()
            && ep.addr == ep_addr
        {
            return ep.stalled = stalled;
        }

        if let Some(ep) = lock.ep_out.as_mut()
            && ep.addr == ep_addr
        {
            ep.stalled = stalled
        }
    }

    fn is_stalled(&self, ep_addr: EndpointAddress) -> bool {
        let mut lock = self.inner.lock().unwrap();

        if let Some(ep) = lock.ep_in.as_mut()
            && ep.addr == ep_addr
        {
            return ep.stalled;
        }

        if let Some(ep) = lock.ep_out.as_mut()
            && ep.addr == ep_addr
        {
            return ep.stalled;
        }

        false
    }

    fn suspend(&self) {}

    fn resume(&self) {}

    fn poll(&self) -> PollResult {
        PollResult::None
    }
}

#[cfg(feature = "transfer")]
impl TransferBus for DummyUsbBus {
    /// Queue a device→host IN transfer. The bytes are captured immediately
    /// (zero-copy-semantics are relaxed in the mock: the data is cloned so the
    /// test can assert it after the buffer is gone).
    fn submit_write(&self, ep: EndpointAddress, buf: &[u8]) -> Result<(), UsbError> {
        let mut lock = self.inner.lock().unwrap();
        let ep_key = u8::from(ep);
        let queue = lock
            .transfer_queues
            .get_mut(&ep_key)
            .ok_or(UsbError::InvalidEndpoint)?;
        queue.queue.push_back(PendingTransfer {
            out_buf: None,
            data: buf.to_vec(),
            complete: false,
            completed_len: 0,
        });
        Ok(())
    }

    /// Queue a host→device OUT transfer.
    ///
    /// # Safety contract (test-only)
    ///
    /// The raw pointer to `buf` is stored in the pending transfer record and
    /// written by `complete_out_transfer`. The caller (firmware transport code
    /// under test) must keep `buf` alive and unmodified until `poll_transfer`
    /// retires the record — identical to the real DMA contract.
    fn submit_read(&self, ep: EndpointAddress, buf: &mut [u8]) -> Result<(), UsbError> {
        let mut lock = self.inner.lock().unwrap();
        let ep_key = u8::from(ep);
        let queue = lock
            .transfer_queues
            .get_mut(&ep_key)
            .ok_or(UsbError::InvalidEndpoint)?;
        let len = buf.len();
        queue.submit_read_count += 1;
        queue.submit_read_lens.push(len);
        queue.queue.push_back(PendingTransfer {
            out_buf: Some((buf.as_mut_ptr(), len)),
            data: Vec::new(),
            complete: false,
            completed_len: 0,
        });
        Ok(())
    }

    /// Retire the oldest completed transfer on `ep`.
    ///
    /// Returns `Some(Ok(n))` if the head entry is complete; `None` otherwise.
    /// Pops the entry on completion (FIFO order).
    fn poll_transfer(&self, ep: EndpointAddress) -> Option<Result<usize, UsbError>> {
        let mut lock = self.inner.lock().unwrap();
        let ep_key = u8::from(ep);
        let queue = lock.transfer_queues.get_mut(&ep_key)?;
        match queue.queue.front() {
            Some(entry) if entry.complete => {
                let n = entry.completed_len;
                queue.queue.pop_front();
                Some(Ok(n))
            }
            _ => None,
        }
    }
}
