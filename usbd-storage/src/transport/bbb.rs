//! Bulk Only Transport (BBB/BOT)

use crate::buffer::Buffer;
use crate::fmt::{info, trace};
#[cfg(feature = "transfer")]
use crate::transfer::TransferBus;
use crate::transport::{CommandStatus, Transport, TransportError};
use core::borrow::BorrowMut;
use core::cmp::min;
use usb_device::UsbError;
use usb_device::bus::{UsbBus, UsbBusAllocator};
use usb_device::class::ControlIn;
use usb_device::class_prelude::DescriptorWriter;
use usb_device::control::{Recipient, RequestType};
use usb_device::endpoint::{Endpoint, In, Out};

/// Bulk Only Transport interface protocol
pub(crate) const TRANSPORT_BBB: u8 = 0x50;

const CLASS_SPECIFIC_BULK_ONLY_MASS_STORAGE_RESET: u8 = 0xFF;
const CLASS_SPECIFIC_GET_MAX_LUN: u8 = 0xFE;

const CBW_SIGNATURE_LE: [u8; 4] = 0x43425355u32.to_le_bytes();
const CSW_SIGNATURE_LE: [u8; 4] = 0x53425355u32.to_le_bytes();

const CBW_LEN: usize = 31;
const CSW_LEN: usize = 13;

struct InvalidCbwError; // Inner transport-specific error

/// Bulk Only Transport error
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BulkOnlyError {
    /// Not enough space to fit additional data
    IoBufferOverflow,
    /// Invalid MAX_LUN value. Refer to USB BBB doc
    InvalidMaxLun,
    /// Transport is not in Data Transfer state
    InvalidState,
    /// Data Transfer expects a full packet to be sent next but not enough data available
    FullPacketExpected,
    /// The IO buffer cannot fit a CBW or a single full packet
    BufferTooSmall,
}

/// Raw Command Block bytes
///
/// The `bytes` field is a truncated slice
pub struct CommandBlock<'a> {
    pub bytes: &'a [u8],
    pub lun: u8,
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum State {
    Idle,                 // no active transfer
    CommandTransfer,      // reading CBW packets
    DataTransferToHost,   // writing bytes to host
    DataTransferFromHost, // reading bytes from host
    DataTransferNoData,   // data transfer not expected
    StatusTransfer,       // writing CSW packets
}

#[repr(u8)]
#[derive(Default, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum DataDirection {
    Out,
    In,
    #[default]
    NotExpected,
}

type BulkOnlyTransportResult<T> = Result<T, TransportError<BulkOnlyError>>;

/// Bulk Only Transport
///
/// Expected to be driven via [write] and [read] methods.
/// All data goes through an underlying IO buffer in both directions.
/// During a Data Transfer, data could be read or written via [read_data], [write_data]
/// and [try_write_data_all] methods.
///
/// [write]: crate::transport::bbb::BulkOnly::write
/// [read]: crate::transport::bbb::BulkOnly::read
/// [read_data]: crate::transport::bbb::BulkOnly::read_data
/// [write_data]: crate::transport::bbb::BulkOnly::write_data
/// [try_write_data_all]: crate::transport::bbb::BulkOnly::try_write_data_all
pub struct BulkOnly<'alloc, Bus: UsbBus, Buf: BorrowMut<[u8]>> {
    in_ep: Endpoint<'alloc, Bus, In>,
    out_ep: Endpoint<'alloc, Bus, Out>,
    buf: Buffer<Buf>,
    state: State,
    cbw: CommandBlockWrapper,
    cs: Option<CommandStatus>,
    max_lun: u8,
    /// Whether a submitted transfer has not yet been retired via `poll_transfer`.
    /// Set on first `write_data_transfer*` / `read_data_transfer` call, cleared
    /// once `poll_transfer` returns `Some(_)`.
    #[cfg(feature = "transfer")]
    transfer_in_flight: bool,
    /// True when the callback is driving this data phase via zero-copy transfers
    /// (`write_data_transfer*` / `read_data_transfer`).  Set on the first such
    /// call, cleared in `end_data_transfer` and `reset()`.
    #[cfg(feature = "transfer")]
    transfer_phase: bool,
}

impl<'alloc, Bus, Buf> BulkOnly<'alloc, Bus, Buf>
where
    Bus: UsbBus,
    Buf: BorrowMut<[u8]>,
{
    /// Creates Bulk Only Transport instance
    ///
    /// # Arguments
    /// * `alloc` - [UsbBusAllocator]
    /// * `packet_size` - Maximum USB packet size. Allowed values: 8,16,32,64
    /// * `max_lun` - The max index of the Logical Unit
    /// * `buf` - The underlying IO buffer. It is **required** to fit at least a `CBW` and/or a single
    ///   packet. It is **recommended** that buffer fits at least one `LBA` size
    ///
    /// # Errors
    /// * [InvalidMaxLun]
    /// * [BufferTooSmall]
    ///
    /// # Panics
    /// Panics if endpoint allocations fails.
    ///
    /// [InvalidMaxLun]: crate::transport::bbb::BulkOnlyError::InvalidMaxLun
    /// [BufferTooSmall]: crate::transport::bbb::BulkOnlyError::BufferTooSmall
    /// [UsbBusAllocator]: usb_device::bus::UsbBusAllocator
    pub fn new(
        alloc: &'alloc UsbBusAllocator<Bus>,
        packet_size: u16,
        max_lun: u8,
        buf: Buf,
    ) -> Result<BulkOnly<'alloc, Bus, Buf>, BulkOnlyError> {
        if max_lun > 0x0F {
            return Err(BulkOnlyError::InvalidMaxLun);
        }

        let buf_len = buf.borrow().len();
        if buf_len < CBW_LEN || buf_len < packet_size as usize {
            return Err(BulkOnlyError::BufferTooSmall);
        }

        Ok(BulkOnly {
            in_ep: alloc.bulk(packet_size),
            out_ep: alloc.bulk(packet_size),
            buf: Buffer::new(buf),
            state: State::Idle,
            cbw: Default::default(),
            cs: Default::default(),
            max_lun,
            #[cfg(feature = "transfer")]
            transfer_in_flight: false,
            #[cfg(feature = "transfer")]
            transfer_phase: false,
        })
    }

    /// Drives a transport by reading a single packet
    pub fn read(&mut self) -> BulkOnlyTransportResult<()> {
        match self.state {
            State::Idle | State::CommandTransfer => self.handle_read_cbw(),
            State::DataTransferFromHost => self.handle_read_from_host(),
            _ => Ok(()),
        }
    }

    /// Drives a transport by writing a single packet
    pub fn write(&mut self) -> BulkOnlyTransportResult<()> {
        match self.state {
            State::StatusTransfer => self.handle_write_csw(),
            State::DataTransferToHost => {
                // When the callback drives the IN data phase via zero-copy transfers
                // (write_data_transfer / write_data_transfer_pipelined), self.buf is
                // empty and data bypasses the staging buffer entirely.  Skip the
                // per-packet write and run check_end_data_transfer directly so the
                // state machine can advance to StatusTransfer once the callback sets
                // a status and the transfer completes.
                #[cfg(feature = "transfer")]
                if self.transfer_phase {
                    return self.check_end_data_transfer();
                }
                self.handle_write_to_host()
            }
            State::DataTransferNoData => self.handle_no_data_transfer(),
            _ => Ok(()),
        }
    }

    /// Sets a `status` of the current command
    ///
    /// This method doesn't try to send a status immediately. However, all further
    /// writes to the IO buffer won't succeed. The transport will try to send all
    /// the contents of the buffer and then `CSW` will be sent.
    ///
    /// # Panics
    /// Panics if called during any by Data Transfer state. Usually, this means an error in
    /// class implementation.
    pub fn set_status(&mut self, status: CommandStatus) {
        assert!(matches!(
            self.state,
            State::DataTransferToHost | State::DataTransferFromHost | State::DataTransferNoData
        ));
        info!("usb: bbb: Set status: {}", status);
        self.cs = Some(status);
    }

    /// Returns a Command Block if present
    pub fn get_command(&self) -> Option<CommandBlock<'_>> {
        match self.state {
            State::Idle | State::CommandTransfer => None,
            _ => Some(CommandBlock {
                bytes: &self.cbw.block[..self.cbw.block_len],
                lun: self.cbw.lun,
            }),
        }
    }

    /// Reads data from the IO buffer returning the number of bytes actually read
    ///
    /// # Arguments
    /// * `dst` - buffer, to read bytes into
    ///
    /// # Errors
    /// Returns [BulkOnlyError::InvalidState] if called
    /// during any but OUT Data Transfer state.
    ///
    /// [BulkOnlyError::InvalidState]: crate::transport::bbb::BulkOnlyError::InvalidState
    pub fn read_data(&mut self, dst: &mut [u8]) -> BulkOnlyTransportResult<usize> {
        if !matches!(self.state, State::DataTransferFromHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }
        Ok(self
            .buf
            .read(|buf| {
                // fill 'dst' or however much is in 'buf'
                let size = min(dst.len(), buf.len());
                dst[..size].copy_from_slice(&buf[..size]);
                Ok::<usize, ()>(size)
            })
            .unwrap())
    }

    /// Writes data from the IO buffer returning the number of bytes actually written
    ///
    /// # Arguments
    /// * `src` - bytes to write
    ///
    /// # Errors
    /// Returns [BulkOnlyError::InvalidState] if called
    /// during any but IN Data Transfer state.
    ///
    /// [BulkOnlyError::InvalidState]: crate::transport::bbb::BulkOnlyError::InvalidState
    pub fn write_data(&mut self, src: &[u8]) -> BulkOnlyTransportResult<usize> {
        if !matches!(self.state, State::DataTransferToHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }
        if !self.status_present() {
            Ok(self
                .buf
                .write(&src[..min(src.len(), self.cbw.data_transfer_len as usize)]))
        } else {
            Err(TransportError::Error(BulkOnlyError::InvalidState))
        }
    }

    /// Tries to write all data from `src` into the IO buffer returning the number of bytes actually written
    ///
    /// # Errors
    /// * [BulkOnlyError::IoBufferOverflow] - if not enough space is available
    /// * [BulkOnlyError::InvalidState] - if called during any but IN Data Transfer state
    ///
    /// [BulkOnlyError::IoBufferOverflow]: crate::transport::bbb::BulkOnlyError::IoBufferOverflow
    /// [BulkOnlyError::InvalidState]: crate::transport::bbb::BulkOnlyError::InvalidState
    pub fn try_write_data_all(&mut self, src: &[u8]) -> BulkOnlyTransportResult<()> {
        if !matches!(self.state, State::DataTransferToHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }
        if !self.status_present() {
            self.buf
                .write_all(
                    src.len(),
                    TransportError::Error(BulkOnlyError::IoBufferOverflow),
                    |dst| {
                        dst[..src.len()].copy_from_slice(src);
                        Ok(src.len())
                    },
                )
                .map(|_| ())
        } else {
            Err(TransportError::Error(BulkOnlyError::InvalidState))
        }
    }

    /// Whether a Command Status has been set
    pub fn has_status(&self) -> bool {
        self.status_present()
    }

    // -----------------------------------------------------------------------
    // Zero-copy transfer methods (feature = "transfer")
    // -----------------------------------------------------------------------

    /// Zero-copy data-IN phase: submit `src` as one transfer on first call,
    /// poll for retirement on subsequent calls.
    ///
    /// Returns the byte count once the transfer is retired; returns
    /// `WouldBlock` while the transfer is in flight.  Updates the data-phase
    /// residue exactly like [`write_data`](Self::write_data) does.
    ///
    /// # Errors
    /// * `TransportError::Usb(WouldBlock)` — transfer primed or still in flight.
    /// * `TransportError::Error(InvalidState)` — not in the IN data-transfer state.
    #[cfg(feature = "transfer")]
    pub fn write_data_transfer<B: TransferBus>(
        &mut self,
        bus: &B,
        src: &[u8],
    ) -> BulkOnlyTransportResult<usize> {
        if !matches!(self.state, State::DataTransferToHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }

        let len = min(src.len(), self.cbw.data_transfer_len as usize);
        let src = &src[..len];

        if !self.transfer_in_flight {
            // The callback is driving this data phase via zero-copy transfers.
            // Set BEFORE the submit attempt: if the submit returns WouldBlock
            // (driver TD budget momentarily full), `write()` must still skip
            // `handle_write_to_host` — otherwise its empty-IO-buffer
            // `FullPacketExpected` error makes `poll_inner` loop the callback
            // forever inside one poll (HW-observed ISR wedge, 2026-06-10).
            // The next poll simply retries the submit.
            self.transfer_phase = true;
            // First call: prime the IN transfer and return WouldBlock.
            bus.submit_write(self.in_ep.address(), src)
                .map_err(TransportError::Usb)?;
            self.transfer_in_flight = true;
            return Err(TransportError::Usb(UsbError::WouldBlock));
        }

        // Subsequent calls: poll for completion.
        match bus.poll_transfer(self.in_ep.address()) {
            None => Err(TransportError::Usb(UsbError::WouldBlock)),
            Some(Err(e)) => {
                self.transfer_in_flight = false;
                Err(TransportError::Usb(e))
            }
            Some(Ok(n)) => {
                self.transfer_in_flight = false;
                self.cbw.data_transfer_len = self.cbw.data_transfer_len.saturating_sub(n as u32);
                trace!(
                    "usb: bbb: write_data_transfer: {} bytes, residue: {}",
                    n, self.cbw.data_transfer_len
                );
                Ok(n)
            }
        }
    }

    /// Zero-copy data-OUT phase: prime `dst` for one transfer on first call,
    /// poll for retirement on subsequent calls.
    ///
    /// Returns the byte count once the transfer is retired; returns
    /// `WouldBlock` while the transfer is in flight.  Updates the data-phase
    /// residue exactly like [`read_data`](Self::read_data) does.
    ///
    /// The caller **must** pass the same `dst` slice on every call for a given
    /// data phase — the slice must remain valid and unmodified until `Ok` is
    /// returned.
    ///
    /// # Errors
    /// * `TransportError::Usb(WouldBlock)` — transfer primed or still in flight.
    /// * `TransportError::Error(InvalidState)` — not in the OUT data-transfer state.
    #[cfg(feature = "transfer")]
    pub fn read_data_transfer<B: TransferBus>(
        &mut self,
        bus: &B,
        dst: &mut [u8],
    ) -> BulkOnlyTransportResult<usize> {
        if !matches!(self.state, State::DataTransferFromHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }

        if !self.transfer_in_flight {
            // Set BEFORE the submit attempt (see write_data_transfer): a
            // WouldBlock submit must leave the phase in transfer mode so the
            // poll loop retries instead of colliding per-packet reads.
            self.transfer_phase = true;
            // Clamp to the announced transfer length so we never consume more
            // than the host promised.
            let want = min(dst.len(), self.cbw.data_transfer_len as usize);
            bus.submit_read(self.out_ep.address(), &mut dst[..want])
                .map_err(TransportError::Usb)?;
            self.transfer_in_flight = true;
            return Err(TransportError::Usb(UsbError::WouldBlock));
        }

        // Subsequent calls: poll for completion.
        match bus.poll_transfer(self.out_ep.address()) {
            None => Err(TransportError::Usb(UsbError::WouldBlock)),
            Some(Err(e)) => {
                self.transfer_in_flight = false;
                Err(TransportError::Usb(e))
            }
            Some(Ok(n)) => {
                self.transfer_in_flight = false;
                self.cbw.data_transfer_len = self.cbw.data_transfer_len.saturating_sub(n as u32);
                trace!(
                    "usb: bbb: read_data_transfer: {} bytes, residue: {}",
                    n, self.cbw.data_transfer_len
                );
                Ok(n)
            }
        }
    }

    /// Submit `src` as a pipelined IN transfer without waiting for the previous
    /// one to retire (FIFO order; driver returns `WouldBlock` when its transfer
    /// budget is full).
    ///
    /// Sets `transfer_phase` on the first call so the ordinary per-packet write
    /// path is skipped while the zero-copy data phase is active.
    ///
    /// Returns `()` on successful submission; callers should drain completed
    /// transfers via [`poll_data_transfer`](Self::poll_data_transfer) to free
    /// driver queue slots.
    ///
    /// # Errors
    /// * `TransportError::Usb(WouldBlock)` — driver queue full; drain first.
    /// * `TransportError::Error(InvalidState)` — not in the IN data-transfer state.
    #[cfg(feature = "transfer")]
    pub fn write_data_transfer_pipelined<B: TransferBus>(
        &mut self,
        bus: &B,
        src: &[u8],
    ) -> BulkOnlyTransportResult<()> {
        if !matches!(self.state, State::DataTransferToHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }

        let len = min(src.len(), self.cbw.data_transfer_len as usize);
        let src = &src[..len];

        // Set BEFORE the submit attempt (see write_data_transfer): a WouldBlock
        // submit must not fall back to the per-packet write path.
        self.transfer_phase = true;
        bus.submit_write(self.in_ep.address(), src)
            .map_err(TransportError::Usb)?;
        Ok(())
    }

    /// Retire at most one previously pipelined IN transfer.
    ///
    /// Returns `Ok(Some(n))` when a transfer completes with `n` bytes, updating
    /// the residue.  Returns `Ok(None)` when no transfer has completed yet.
    ///
    /// # Errors
    /// * `TransportError::Usb(_)` — hardware error on the retired transfer.
    /// * `TransportError::Error(InvalidState)` — not in the IN data-transfer state.
    #[cfg(feature = "transfer")]
    pub fn poll_data_transfer<B: TransferBus>(
        &mut self,
        bus: &B,
    ) -> BulkOnlyTransportResult<Option<usize>> {
        if !matches!(self.state, State::DataTransferToHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }

        match bus.poll_transfer(self.in_ep.address()) {
            None => Ok(None),
            Some(Err(e)) => Err(TransportError::Usb(e)),
            Some(Ok(n)) => {
                self.cbw.data_transfer_len = self.cbw.data_transfer_len.saturating_sub(n as u32);
                trace!(
                    "usb: bbb: poll_data_transfer: {} bytes, residue: {}",
                    n, self.cbw.data_transfer_len
                );
                Ok(Some(n))
            }
        }
    }

    /// Finalize a transfer-driven data phase: when the callback has set a
    /// command status (and no transfer is in flight), run
    /// `check_end_data_transfer` to advance the state machine from `Data*` to
    /// `StatusTransfer`.
    ///
    /// This is the OUT-phase mirror of the per-packet `handle_read_from_host`
    /// tail, omitting the colliding `read_packet` so the CSW is built and
    /// flushed after the bulk transfer has moved all the data.
    #[cfg(feature = "transfer")]
    pub fn finish_data_transfer_phase(&mut self) -> BulkOnlyTransportResult<()> {
        self.check_end_data_transfer()
    }

    /// Returns `true` while the OUT data phase is being driven by the callback
    /// via zero-copy transfers (`read_data_transfer`).
    ///
    /// `poll_transfer` uses this to skip the ordinary per-packet `read()` while
    /// a large OUT transfer owns the endpoint — a colliding `read_packet` would
    /// re-prime the endpoint with a small staging buffer, blocking the bulk
    /// transfer and consuming the host's data into the wrong buffer.
    #[cfg(feature = "transfer")]
    pub(crate) fn is_data_transfer_phase(&self) -> bool {
        matches!(self.state, State::DataTransferFromHost) && self.transfer_phase
    }

    fn handle_read_cbw(&mut self) -> BulkOnlyTransportResult<()> {
        // CBW lazily primes one staging transfer here when the class polls while
        // Idle.  This means the CBW is effectively re-primed right after CSW
        // completion, killing most of the NAK window by construction.
        self.read_packet()?; // propagate if error or WouldBlock

        if self.buf.available_read() >= CBW_LEN {
            // try parse CBW if enough data available
            match self.try_parse_cbw() {
                Ok(cbw) => {
                    info!("usb: bbb: Recv CBW: {}", cbw);
                    self.start_data_transfer(cbw);
                }
                Err(_) => {
                    // Spec. 6.6.1
                    self.stall_eps();
                    self.reset();
                }
            }
        } else {
            // we've read something but it's not enough yet
            self.enter_state(State::CommandTransfer)
        }
        Ok(())
    }

    fn handle_read_from_host(&mut self) -> BulkOnlyTransportResult<()> {
        if !self.status_present() {
            let count = self.read_packet()?; // propagate if error or WouldBlock
            self.cbw.data_transfer_len = self.cbw.data_transfer_len.saturating_sub(count as u32);
            trace!("usb: bbb: Data residue: {}", self.cbw.data_transfer_len);
        }
        self.check_end_data_transfer()
    }

    fn handle_write_to_host(&mut self) -> BulkOnlyTransportResult<()> {
        // Do not send a short packet if there is not enough data in the buffer. Some drivers
        // consider this as an error.
        // If the next packet is expected to be full (according to data residue) but it isn't,
        // return an error

        let max_packet_size = self.packet_size() as u32;

        // if enough data is expected by data transfer or if there is no status.
        // therefore, a full packet is not expected if data transfer is interrupted
        // by failing a command
        let full_packet_expected =
            self.cbw.data_transfer_len >= max_packet_size && !self.status_present();

        let full_packet = self.buf.available_read() >= max_packet_size as usize;
        let full_packet_or_zero = full_packet || !full_packet_expected;

        if full_packet_or_zero {
            // attempt to send data from buffer if any
            if self.buf.available_read() > 0 {
                let count = self.write_packet()?; // propagate if error
                self.cbw.data_transfer_len =
                    self.cbw.data_transfer_len.saturating_sub(count as u32);
                trace!("usb: bbb: Data residue: {}", self.cbw.data_transfer_len);
            }
            self.check_end_data_transfer()
        } else {
            Err(TransportError::Error(BulkOnlyError::FullPacketExpected))
        }
    }

    fn handle_no_data_transfer(&mut self) -> BulkOnlyTransportResult<()> {
        self.check_end_data_transfer()
    }

    fn handle_write_csw(&mut self) -> BulkOnlyTransportResult<()> {
        self.write_packet()?; // propagate if error
        if self.buf.available_read() == 0 {
            self.enter_state(State::Idle) // done with status transfer
        }
        Ok(())
    }

    fn check_end_data_transfer(&mut self) -> BulkOnlyTransportResult<()> {
        match self.state {
            State::DataTransferNoData | State::DataTransferFromHost
                // command is passed or failed. IO buffer is irrelevant. end data transfer
                if self.cs.is_some() => {
                    self.end_data_transfer()?;
                }
            State::DataTransferToHost
                // command is passed or failed. empty IO buffer first. if empty, end data transfer
                if self.cs.is_some() && self.buf.available_read() == 0 => {
                    self.end_data_transfer()?;
                }
            _ => {}
        }

        Ok(())
    }

    fn end_data_transfer(&mut self) -> BulkOnlyTransportResult<()> {
        // spec. 6.7.2 and 6.7.3
        if self.cbw.data_transfer_len > 0 {
            match self.state {
                State::DataTransferToHost => {
                    //TODO: send zlp right here
                    self.stall_in_ep();
                }
                State::DataTransferFromHost => {
                    self.stall_out_ep();
                }
                _ => {}
            }
        }

        // Clear transfer state before moving to the status phase.
        #[cfg(feature = "transfer")]
        {
            self.transfer_in_flight = false;
            self.transfer_phase = false;
        }

        // write CSW into buffer
        // CSW serialization is structural when using TransferBus: the driver's
        // depth-1 IN queue makes later IN submits return WouldBlock until the
        // CSW retires, so the next command cannot be primed ahead of this CSW.
        let csw = self.build_csw().unwrap();
        self.buf.clean();
        self.buf.write(csw.as_slice());

        self.enter_state(State::StatusTransfer);
        self.write() // flush
    }

    #[inline]
    fn status_present(&self) -> bool {
        self.cs.is_some()
    }

    fn build_csw(&mut self) -> Option<[u8; CSW_LEN]> {
        self.cs.map(|status| {
            let mut csw = [0u8; CSW_LEN];
            csw[..4].copy_from_slice(CSW_SIGNATURE_LE.as_slice());
            csw[4..8].copy_from_slice(self.cbw.tag.to_le_bytes().as_slice());
            csw[8..12].copy_from_slice(self.cbw.data_transfer_len.to_le_bytes().as_slice());
            csw[12..].copy_from_slice(&[status as u8]);
            csw
        })
    }

    /// The caller must ensure that there is enough data available
    fn try_parse_cbw(&mut self) -> Result<CommandBlockWrapper, InvalidCbwError> {
        debug_assert!(matches!(self.state, State::Idle | State::CommandTransfer));
        debug_assert!(self.buf.available_read() >= CBW_LEN);

        // read CBW from buf
        let mut raw_cbw = [0u8; CBW_LEN];
        self.buf
            .read::<()>(|buf| {
                raw_cbw.copy_from_slice(&buf[..CBW_LEN]); // buf.len() checked in the beginning
                Ok(CBW_LEN)
            })
            .unwrap();

        // check if CBW is valid. Spec. 6.2.1
        if !raw_cbw.starts_with(&CBW_SIGNATURE_LE) {
            return Err(InvalidCbwError);
        }

        CommandBlockWrapper::from_le_bytes(&raw_cbw[4..]) // parse CBW (skipping signature)
    }

    fn start_data_transfer(&mut self, mut cbw: CommandBlockWrapper) {
        debug_assert!(matches!(self.state, State::Idle | State::CommandTransfer));

        // build new state
        match cbw.direction {
            DataDirection::Out => {
                self.enter_state(State::DataTransferFromHost);
            }
            DataDirection::In => {
                self.enter_state(State::DataTransferToHost);
            }
            DataDirection::NotExpected => {
                self.enter_state(State::DataTransferNoData);
                cbw.data_transfer_len = 0; // original value ignored
            }
        };
        self.cbw = cbw;
    }

    #[inline]
    fn packet_size(&self) -> usize {
        self.in_ep.max_packet_size() as usize // same for both In and Out EPs
    }

    fn read_packet(&mut self) -> BulkOnlyTransportResult<usize> {
        let count = self.buf.write_all(
            self.packet_size(),
            TransportError::Error(BulkOnlyError::IoBufferOverflow),
            |buf| match self.out_ep.read(buf) {
                Ok(count) => Ok(count),
                Err(UsbError::WouldBlock) => Ok(0),
                Err(err) => Err(TransportError::Usb(err)),
            },
        )?;

        trace!(
            "usb: bbb: Read bytes: {}, buf available: {}",
            count,
            self.buf.available_read()
        );

        if count == 0 {
            Err(TransportError::Usb(UsbError::WouldBlock))
        } else {
            Ok(count)
        }
    }

    /// Write single packet from [buf] returning number of bytes actually written
    fn write_packet(&mut self) -> BulkOnlyTransportResult<usize> {
        let packet_size = self.packet_size();
        let count = self.buf.read(|buf| {
            if !buf.is_empty() {
                match self.in_ep.write(&buf[..min(packet_size, buf.len())]) {
                    Ok(count) => Ok(count),
                    Err(UsbError::WouldBlock) => Ok(0),
                    Err(err) => Err(TransportError::Usb(err)),
                }
            } else {
                Ok(0) // not enough data in buf, though it's not an error
            }
        })?;

        trace!(
            "usb: bbb: Wrote bytes: {}, buf available: {}",
            count,
            self.buf.available_read()
        );

        if count == 0 {
            Err(TransportError::Usb(UsbError::WouldBlock))
        } else {
            Ok(count)
        }
    }

    #[inline]
    fn stall_eps(&self) {
        self.stall_in_ep();
        self.stall_out_ep();
    }

    #[inline]
    fn stall_in_ep(&self) {
        info!("usb: bbb: Stall IN ep");
        self.in_ep.stall();
    }

    #[inline]
    fn stall_out_ep(&self) {
        info!("usb: bbb: Stall OUT ep");
        self.out_ep.stall();
    }

    #[inline]
    fn enter_state(&mut self, state: State) {
        info!("usb: bbb: Enter state: {}", state);
        // clean if going Idle
        if matches!(state, State::Idle) {
            self.buf.clean();
            self.cbw = Default::default();
            self.cs = None;
        }
        self.state = state;
    }
}

impl<Bus, Buf> Transport for BulkOnly<'_, Bus, Buf>
where
    Bus: UsbBus,
    Buf: BorrowMut<[u8]>,
{
    const PROTO: u8 = TRANSPORT_BBB;
    type Bus = Bus;

    fn get_endpoint_descriptors(&self, writer: &mut DescriptorWriter) -> Result<(), UsbError> {
        writer.endpoint(&self.in_ep)?;
        writer.endpoint(&self.out_ep)?;
        Ok(())
    }

    fn reset(&mut self) {
        info!("usb: bbb: Recv reset");
        self.in_ep.unstall();
        self.out_ep.unstall();
        #[cfg(feature = "transfer")]
        {
            self.transfer_in_flight = false;
            self.transfer_phase = false;
        }
        self.enter_state(State::Idle);
    }

    fn control_in(&mut self, xfer: ControlIn<Self::Bus>) {
        let req = xfer.request();

        // not interested in this request
        if !(req.request_type == RequestType::Class && req.recipient == Recipient::Interface) {
            return;
        }

        info!("usb: bbb: Recv ctrl_in: {}", req);

        match req.request {
            // Spec. section 3.1
            CLASS_SPECIFIC_BULK_ONLY_MASS_STORAGE_RESET => {}
            // Spec. section 3.2
            CLASS_SPECIFIC_GET_MAX_LUN => {
                // always respond with LUN
                xfer.accept_with(&[self.max_lun])
                    .expect("Failed to accept Get Max Lun!");
            }
            _ => {}
        }
    }
}

#[derive(Default, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct CommandBlockWrapper {
    tag: u32,
    data_transfer_len: u32,
    direction: DataDirection,
    lun: u8,
    block_len: usize,
    block: [u8; 16],
}

impl CommandBlockWrapper {
    fn from_le_bytes(value: &[u8]) -> Result<Self, InvalidCbwError> {
        const MIN_CB_LEN: u8 = 1;
        const MAX_CB_LEN: u8 = 16;

        let block_len = value[10];

        if !(MIN_CB_LEN..=MAX_CB_LEN).contains(&block_len) {
            return Err(InvalidCbwError);
        }

        Ok(CommandBlockWrapper {
            tag: u32::from_le_bytes(value[..4].try_into().unwrap()),
            data_transfer_len: u32::from_le_bytes(value[4..8].try_into().unwrap()),
            direction: if u32::from_le_bytes(value[4..8].try_into().unwrap()) != 0 {
                if (value[8] & (1 << 7)) > 0 {
                    DataDirection::In
                } else {
                    DataDirection::Out
                }
            } else {
                DataDirection::NotExpected
            },
            lun: value[9] & 0b00001111,
            block_len: block_len as usize,
            block: value[11..].try_into().unwrap(), // ok, because we checked a length
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::bbb::BulkOnly;
    use crate::transport::bbb::State::DataTransferFromHost;
    use usb_device::bus::{PollResult, UsbBus, UsbBusAllocator};
    use usb_device::class_prelude::{EndpointAddress, EndpointType};
    use usb_device::{UsbDirection, UsbError};

    struct DummyBus;

    impl UsbBus for DummyBus {
        fn alloc_ep(
            &mut self,
            _ep_dir: UsbDirection,
            _ep_addr: Option<EndpointAddress>,
            _ep_type: EndpointType,
            _max_packet_size: u16,
            _interval: u8,
        ) -> usb_device::Result<EndpointAddress> {
            Ok(EndpointAddress::from(0))
        }

        fn enable(&mut self) {}

        fn reset(&self) {}
        fn set_device_address(&self, _addr: u8) {}

        fn write(&self, _ep_addr: EndpointAddress, _buf: &[u8]) -> usb_device::Result<usize> {
            Err(UsbError::InvalidEndpoint)
        }

        fn read(&self, _ep_addr: EndpointAddress, _buf: &mut [u8]) -> usb_device::Result<usize> {
            Err(UsbError::InvalidEndpoint)
        }

        fn set_stalled(&self, _ep_addr: EndpointAddress, _stalled: bool) {}
        fn is_stalled(&self, _ep_addr: EndpointAddress) -> bool {
            false
        }
        fn suspend(&self) {}
        fn resume(&self) {}
        fn poll(&self) -> PollResult {
            PollResult::None
        }
    }

    #[test]
    fn should_read_data_into_small_buffer() {
        const BUF_SIZE: usize = 512;
        const N: usize = 123;

        let alloc = UsbBusAllocator::new(DummyBus);
        let mut bbb = BulkOnly::new(&alloc, 8, 0, vec![0u8; BUF_SIZE]).unwrap();
        bbb.state = DataTransferFromHost;
        bbb.buf.write([0xFFu8; BUF_SIZE].as_slice()); // fill the buffer

        assert_eq!(N, bbb.read_data([0u8; N].as_mut_slice()).unwrap());
    }

    /// A [`DummyBus`]-alike whose `TransferBus` submit methods always return
    /// `WouldBlock` (driver TD budget full), for the submit-refused corner.
    #[cfg(feature = "transfer")]
    struct WouldBlockTransferBus;

    #[cfg(feature = "transfer")]
    impl UsbBus for WouldBlockTransferBus {
        fn alloc_ep(
            &mut self,
            ep_dir: UsbDirection,
            _ep_addr: Option<EndpointAddress>,
            _ep_type: EndpointType,
            _max_packet_size: u16,
            _interval: u8,
        ) -> usb_device::Result<EndpointAddress> {
            Ok(EndpointAddress::from_parts(1, ep_dir))
        }
        fn enable(&mut self) {}
        fn reset(&self) {}
        fn set_device_address(&self, _addr: u8) {}
        fn write(&self, _ep_addr: EndpointAddress, buf: &[u8]) -> usb_device::Result<usize> {
            Ok(buf.len())
        }
        fn read(&self, _ep_addr: EndpointAddress, _buf: &mut [u8]) -> usb_device::Result<usize> {
            Err(UsbError::WouldBlock)
        }
        fn set_stalled(&self, _ep_addr: EndpointAddress, _stalled: bool) {}
        fn is_stalled(&self, _ep_addr: EndpointAddress) -> bool {
            false
        }
        fn suspend(&self) {}
        fn resume(&self) {}
        fn poll(&self) -> PollResult {
            PollResult::None
        }
    }

    #[cfg(feature = "transfer")]
    impl crate::transfer::TransferBus for WouldBlockTransferBus {
        fn submit_write(&self, _ep: EndpointAddress, _buf: &[u8]) -> usb_device::Result<()> {
            Err(UsbError::WouldBlock)
        }
        fn submit_read(&self, _ep: EndpointAddress, _buf: &mut [u8]) -> usb_device::Result<()> {
            Err(UsbError::WouldBlock)
        }
        fn poll_transfer(&self, _ep: EndpointAddress) -> Option<usb_device::Result<usize>> {
            None
        }
    }

    /// Regression for the chain MSC ISR wedge (HW, 2026-06-10, cycle 2): when
    /// the zero-copy submit is refused with `WouldBlock` (driver TD budget
    /// momentarily full), the data phase must STAY in transfer mode. Pre-fix,
    /// `transfer_phase` was only set after a successful submit, so the
    /// subsequent `write()` ran `handle_write_to_host` on an empty IO buffer →
    /// `Err(FullPacketExpected)` → `Scsi::poll_inner` looped the callback
    /// forever inside one poll, starving EP0 until the device fell off the bus.
    #[cfg(feature = "transfer")]
    #[test]
    fn wouldblock_submit_keeps_transfer_phase_no_fullpacket_spin() {
        use crate::transport::TransportError;
        use usb_device::device::{UsbDeviceBuilder, UsbVidPid};

        let alloc = UsbBusAllocator::new(WouldBlockTransferBus);
        let mut bbb = BulkOnly::new(&alloc, 64, 0, vec![0u8; 512]).unwrap();
        let _usb_dev = UsbDeviceBuilder::new(&alloc, UsbVidPid(0x0000, 0x0000)).build();

        // IN data phase for a 512-byte READ; no status yet.
        bbb.state = crate::transport::bbb::State::DataTransferToHost;
        bbb.cbw.data_transfer_len = 512;

        // First callback call: the submit is refused with WouldBlock.
        let src = [0u8; 512];
        let r = bbb.write_data_transfer(&WouldBlockTransferBus, &src);
        assert!(
            matches!(r, Err(TransportError::Usb(UsbError::WouldBlock))),
            "refused submit must surface WouldBlock, got {r:?}"
        );

        // The poll loop then drives write(): it must NOT degenerate into
        // FullPacketExpected (the pre-fix infinite-callback-loop trigger);
        // the phase stays in transfer mode and the next poll retries.
        let w = bbb.write();
        assert!(
            w.is_ok(),
            "write() after a WouldBlock submit must be a quiet no-op, got {w:?}"
        );
    }
}
