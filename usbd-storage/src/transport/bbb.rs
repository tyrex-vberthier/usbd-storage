//! Bulk Only Transport (BBB/BOT)

use crate::buffer::Buffer;
use crate::fmt::{info, trace};
use crate::transport::{CommandStatus, Transport, TransportError};
use core::borrow::BorrowMut;
use core::cmp::min;
use usb_device::bus::{UsbBus, UsbBusAllocator};
use usb_device::class::ControlIn;
use usb_device::class_prelude::DescriptorWriter;
use usb_device::control::{Recipient, RequestType};
use usb_device::endpoint::{Endpoint, In, Out};
use usb_device::UsbError;

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
    /// Whether a bulk big-transfer dTD is currently in flight on the bus.
    ///
    /// Set to `true` after priming via [`bulk_write_data`] or [`bulk_read_data`]
    /// and cleared when [`BulkBus::bulk_poll`] returns `Some(n)`.  Necessary
    /// because after a completed transfer the EP is unprimed, so a bus-state-only
    /// check cannot distinguish "never primed" from "just completed".
    bulk_in_flight: bool,
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
            bulk_in_flight: false,
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
            State::DataTransferToHost => self.handle_write_to_host(),
            State::DataTransferNoData => self.handle_no_data_transfer(),
            _ => Ok(()),
        }
    }

    /// Ring-aware variant of [`write`](Self::write).
    ///
    /// Identical to `write` except the CSW status phase is serialized against the
    /// IN ring: `in_drained` must report whether the IN endpoint's multi-TD ring
    /// has fully drained, so the transport only advances to `Idle` once the host
    /// has actually read the CSW. Drive this (instead of `write`) from
    /// [`Scsi::poll_ring`](crate::subclass::scsi::Scsi::poll_ring).
    #[cfg(feature = "ring")]
    pub fn write_ring(&mut self, in_drained: bool) -> BulkOnlyTransportResult<()> {
        match self.state {
            State::StatusTransfer => self.handle_write_csw_ring(in_drained),
            State::DataTransferToHost => self.handle_write_to_host(),
            State::DataTransferNoData => self.handle_no_data_transfer(),
            _ => Ok(()),
        }
    }

    /// The IN (device→host) bulk endpoint address.
    ///
    /// Exposed so a ring-aware driver loop can query the bus for IN-ring drain
    /// state (see [`write_ring`](Self::write_ring)).
    #[cfg(feature = "ring")]
    pub fn in_ep_address(&self) -> usb_device::endpoint::EndpointAddress {
        self.in_ep.address()
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
        // The closure always returns Ok, so the outer Result is always Ok too.
        Ok(self
            .buf
            .read(|buf| {
                // fill 'dst' or however much is in 'buf'
                let size = min(dst.len(), buf.len());
                dst[..size].copy_from_slice(&buf[..size]);
                Ok::<usize, core::convert::Infallible>(size)
            })
            .unwrap_or(0))
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

    /// Whether the transport is currently in the OUT (host→device) data phase.
    ///
    /// During this phase the bulk fast-path callback owns the shared OUT
    /// endpoint (it primes a single large dTD via
    /// [`bulk_read_data`](BulkOnly::bulk_read_data)).  The ordinary per-packet
    /// [`read`](BulkOnly::read) path MUST NOT run in this phase: its
    /// `read_packet` re-primes a 512-byte per-packet OUT transfer on the same
    /// endpoint, which both blocks the bulk prime (the endpoint stays primed)
    /// and consumes the host's write data into the transport ring buffer
    /// instead of the caller's bulk buffer.  `poll_bulk` queries this to skip
    /// the per-packet read while the bulk data phase is in flight.
    #[cfg(feature = "bbb")]
    pub(crate) fn is_bulk_out_phase(&self) -> bool {
        matches!(self.state, State::DataTransferFromHost)
    }

    /// Advance the OUT data phase to the status (CSW) phase once the bulk
    /// callback has set a command status, WITHOUT performing a per-packet read.
    ///
    /// Mirrors the tail of [`handle_read_from_host`](BulkOnly::handle_read_from_host)
    /// (`check_end_data_transfer`) but omits the colliding `read_packet`, so the
    /// CSW is still built and flushed after the bulk dTD has moved all the data.
    #[cfg(feature = "bbb")]
    pub(crate) fn finish_bulk_out_phase(&mut self) -> BulkOnlyTransportResult<()> {
        self.check_end_data_transfer()
    }

    fn handle_read_cbw(&mut self) -> BulkOnlyTransportResult<()> {
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

    #[cfg(not(feature = "ring"))]
    fn handle_read_from_host(&mut self) -> BulkOnlyTransportResult<()> {
        if !self.status_present() {
            let count = self.read_packet()?; // propagate if error or WouldBlock
            self.cbw.data_transfer_len = self.cbw.data_transfer_len.saturating_sub(count as u32);
            trace!("usb: bbb: Data residue: {}", self.cbw.data_transfer_len);
        }
        self.check_end_data_transfer()
    }

    #[cfg(feature = "ring")]
    fn handle_read_from_host(&mut self) -> BulkOnlyTransportResult<()> {
        if !self.status_present() {
            // Ring pump: drain every packet the ring delivers this poll, not just one.
            loop {
                match self.read_packet() {
                    Ok(count) => {
                        self.cbw.data_transfer_len =
                            self.cbw.data_transfer_len.saturating_sub(count as u32);
                        trace!("usb: bbb: Data residue: {}", self.cbw.data_transfer_len);
                    }
                    // ring drained (no more completed OUT slots) — resume next poll
                    Err(TransportError::Usb(UsbError::WouldBlock)) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        self.check_end_data_transfer()
    }

    #[cfg(not(feature = "ring"))]
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

    #[cfg(feature = "ring")]
    fn handle_write_to_host(&mut self) -> BulkOnlyTransportResult<()> {
        let max_packet_size = self.packet_size() as u32;
        let full_packet_expected =
            self.cbw.data_transfer_len >= max_packet_size && !self.status_present();
        let full_packet = self.buf.available_read() >= max_packet_size as usize;
        let full_packet_or_zero = full_packet || !full_packet_expected;
        if full_packet_or_zero {
            // Ring pump: push packets until the ring is full (WouldBlock) or the
            // IO buffer drains. Stock sends exactly one packet per poll.
            while self.buf.available_read() > 0 {
                match self.write_packet() {
                    Ok(count) => {
                        self.cbw.data_transfer_len =
                            self.cbw.data_transfer_len.saturating_sub(count as u32);
                        trace!("usb: bbb: Data residue: {}", self.cbw.data_transfer_len);
                    }
                    // ring full — resume next poll
                    Err(TransportError::Usb(UsbError::WouldBlock)) => break,
                    Err(e) => return Err(e),
                }
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

    /// CSW status phase for a multi-TD ring bus.
    ///
    /// Unlike [`handle_write_csw`], the transition to `Idle` is gated on the IN
    /// ring being fully **drained** (`in_drained`), not merely on the CSW having
    /// been written into the IO buffer. A multi-TD ring accepts a `write` while
    /// earlier dTDs are still in flight, so the stock "Idle once the buffer is
    /// empty" rule would let the *next* command's response be primed ahead of this
    /// CSW — the host then reads a stale or duplicate CSW (a BOT phase error that
    /// triggers a device reset). Keeping the ring empty at every command boundary
    /// preserves BOT serialization while still allowing pipelining *within* a
    /// command's data phase.
    #[cfg(feature = "ring")]
    fn handle_write_csw_ring(&mut self, in_drained: bool) -> BulkOnlyTransportResult<()> {
        if self.buf.available_read() > 0 {
            // CSW not yet primed into the ring. Prime it; a ring-full WouldBlock
            // just means retry next poll (data dTDs still occupying the ring).
            match self.write_packet() {
                Ok(_) | Err(TransportError::Usb(UsbError::WouldBlock)) => Ok(()),
                Err(e) => Err(e),
            }
        } else if in_drained {
            // CSW primed AND delivered (ring drained) — the command is truly done.
            self.enter_state(State::Idle);
            Ok(())
        } else {
            // CSW primed but still in flight — wait for the host to read it.
            Ok(())
        }
    }

    fn check_end_data_transfer(&mut self) -> BulkOnlyTransportResult<()> {
        match self.state {
            State::DataTransferNoData | State::DataTransferFromHost => {
                // command is passed or failed. IO buffer is irrelevant. end data transfer
                if self.cs.is_some() {
                    self.end_data_transfer()?;
                }
            }
            State::DataTransferToHost => {
                // command is passed or failed. empty IO buffer first. if empty, end data transfer
                if self.cs.is_some() && self.buf.available_read() == 0 {
                    self.end_data_transfer()?;
                }
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

        // write CSW into buffer — cs must be Some here (enforced by check_end_data_transfer)
        let csw = self
            .build_csw()
            .ok_or(TransportError::Error(BulkOnlyError::InvalidState))?;
        self.buf.clean();
        self.buf.write(csw.as_slice());

        self.enter_state(State::StatusTransfer);
        // Flush (prime) the CSW. On the ring path we must NOT advance to Idle here:
        // the CSW has only been primed into the multi-TD ring, not yet delivered to
        // the host. `poll_ring` drives the StatusTransfer→Idle transition once the
        // IN ring has drained, so the next command's response cannot pipeline ahead
        // of this CSW (which the host would read as a stale/duplicate status).
        #[cfg(feature = "ring")]
        {
            self.handle_write_csw_ring(false)
        }
        #[cfg(not(feature = "ring"))]
        {
            self.write() // flush
        }
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
        // The closure always returns Ok; unwrap_or(0) is unreachable but avoids unwrap().
        self.buf
            .read::<core::convert::Infallible>(|buf| {
                raw_cbw.copy_from_slice(&buf[..CBW_LEN]); // buf.len() checked in the beginning
                Ok(CBW_LEN)
            })
            .unwrap_or(0);

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
        // clean if going Idle — also clear the bulk in-flight flag so a stale
        // flag from a previous command cannot leak into the next one.
        if matches!(state, State::Idle) {
            self.buf.clean();
            self.cbw = Default::default();
            self.cs = None;
            self.bulk_in_flight = false;
        }
        self.state = state;
    }
}

/// Big-transfer data-phase methods — available on any bus that implements [`crate::bulk::BulkBus`].
///
/// These bypass the per-packet IO buffer and hand an entire slice to the bus
/// controller as a single bulk transfer descriptor (dTD).  Use them only for
/// the READ/WRITE *data* phase; CBW, CSW, and SPC small-data paths continue to
/// use the existing [`write_data`] / [`try_write_data_all`] helpers.
///
/// [`write_data`]: BulkOnly::write_data
/// [`try_write_data_all`]: BulkOnly::try_write_data_all
#[cfg(feature = "bbb")]
impl<'alloc, Bus, Buf> BulkOnly<'alloc, Bus, Buf>
where
    Bus: UsbBus + crate::bulk::BulkBus,
    Buf: BorrowMut<[u8]>,
{
    /// Bulk IN data phase: prime `src` as ONE multi-packet transfer descriptor.
    ///
    /// Non-blocking: the first call primes the transfer and returns
    /// [`TransportError::Usb(UsbError::WouldBlock)`].  Subsequent calls poll for
    /// completion; once the controller confirms the dTD is done they return
    /// `Ok(n)` and decrement the residue.
    ///
    /// The caller **must** pass the same `src` slice on every call for a given
    /// data phase — the slice must remain valid until `Ok` is returned.
    ///
    /// # Errors
    /// * [`TransportError::Usb(UsbError::WouldBlock)`] — transfer primed or still
    ///   in flight; call again on the next poll cycle.
    /// * [`TransportError::Error(BulkOnlyError::InvalidState)`] — not currently
    ///   in the IN data-transfer state.
    pub fn bulk_write_data(&mut self, bus: &Bus, src: &[u8]) -> BulkOnlyTransportResult<usize> {
        if !matches!(self.state, State::DataTransferToHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }
        // Clamp to whatever residue remains.
        let len = min(src.len(), self.cbw.data_transfer_len as usize);
        let src = &src[..len];

        let ep = self.in_ep.address();

        if !self.bulk_in_flight {
            // First call: prime the transfer and return WouldBlock.
            crate::bulk::BulkBus::bulk_write(bus, ep, src).map_err(TransportError::Usb)?;
            self.bulk_in_flight = true;
            return Err(TransportError::Usb(UsbError::WouldBlock));
        }

        // Subsequent calls: check whether the controller has completed the dTD.
        match crate::bulk::BulkBus::bulk_poll(bus, ep) {
            Some(n) => {
                self.bulk_in_flight = false;
                self.cbw.data_transfer_len = self.cbw.data_transfer_len.saturating_sub(n as u32);
                trace!(
                    "usb: bbb: bulk_write_data: {} bytes, residue: {}",
                    n,
                    self.cbw.data_transfer_len
                );
                Ok(n)
            }
            None => Err(TransportError::Usb(UsbError::WouldBlock)),
        }
    }

    /// Bulk OUT data phase: prime `dst` for one multi-packet transfer descriptor.
    ///
    /// Non-blocking: the first call primes the OUT endpoint and returns
    /// [`TransportError::Usb(UsbError::WouldBlock)`].  Subsequent calls poll for
    /// completion; once the host has delivered the data they return `Ok(n)` and
    /// decrement the residue.
    ///
    /// The caller **must** pass the same `dst` slice on every call for a given
    /// data phase — the slice must remain valid and unmodified until `Ok` is
    /// returned.
    ///
    /// # Errors
    /// * [`TransportError::Usb(UsbError::WouldBlock)`] — transfer primed or still
    ///   in flight; call again on the next poll cycle.
    /// * [`TransportError::Error(BulkOnlyError::InvalidState)`] — not currently
    ///   in the OUT data-transfer state.
    pub fn bulk_read_data(&mut self, bus: &Bus, dst: &mut [u8]) -> BulkOnlyTransportResult<usize> {
        if !matches!(self.state, State::DataTransferFromHost) {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }

        let ep = self.out_ep.address();

        if !self.bulk_in_flight {
            // First call: prime the OUT endpoint and return WouldBlock.
            crate::bulk::BulkBus::bulk_read_prime(bus, ep, dst).map_err(TransportError::Usb)?;
            self.bulk_in_flight = true;
            return Err(TransportError::Usb(UsbError::WouldBlock));
        }

        // Subsequent calls: check whether the host has delivered the data.
        match crate::bulk::BulkBus::bulk_poll(bus, ep) {
            Some(n) => {
                self.bulk_in_flight = false;
                self.cbw.data_transfer_len = self.cbw.data_transfer_len.saturating_sub(n as u32);
                trace!(
                    "usb: bbb: bulk_read_data: {} bytes, residue: {}",
                    n,
                    self.cbw.data_transfer_len
                );
                Ok(n)
            }
            None => Err(TransportError::Usb(UsbError::WouldBlock)),
        }
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

        // These slices are always exactly 4 / 4 / 16 bytes given the CBW layout;
        // map the (unreachable) TryInto failure to InvalidCbwError rather than
        // unwrapping.
        let tag = u32::from_le_bytes(value[..4].try_into().map_err(|_| InvalidCbwError)?);
        let data_transfer_len =
            u32::from_le_bytes(value[4..8].try_into().map_err(|_| InvalidCbwError)?);
        let direction = if data_transfer_len != 0 {
            if (value[8] & (1 << 7)) > 0 {
                DataDirection::In
            } else {
                DataDirection::Out
            }
        } else {
            DataDirection::NotExpected
        };
        let block: [u8; 16] = value[11..].try_into().map_err(|_| InvalidCbwError)?;

        Ok(CommandBlockWrapper {
            tag,
            data_transfer_len,
            direction,
            lun: value[9] & 0b00001111,
            block_len: block_len as usize,
            block,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::bulk::BulkBus;
    use crate::transport::bbb::BulkOnly;
    use crate::transport::bbb::State::{DataTransferFromHost, DataTransferToHost};
    use crate::transport::CommandStatus;
    use crate::transport::TransportError;
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

    /// Extend `DummyBus` with a `BulkBus` impl for testing the big-transfer
    /// path without a real `imxrt-usbd` controller.
    ///
    /// `bulk_write` reports the slice length as accepted.
    /// `bulk_read_prime` always succeeds.
    /// `bulk_poll` returns `Some(512)` — simulates immediate hardware completion.
    impl BulkBus for DummyBus {
        fn bulk_write(&self, _ep: EndpointAddress, buf: &[u8]) -> Result<usize, UsbError> {
            Ok(buf.len())
        }

        fn bulk_read_prime(&self, _ep: EndpointAddress, _buf: &mut [u8]) -> Result<(), UsbError> {
            Ok(())
        }

        fn bulk_poll(&self, _ep: EndpointAddress) -> Option<usize> {
            // Simulates immediate hardware completion.
            Some(512)
        }

        fn in_ep_drained(&self, _ep: EndpointAddress) -> bool {
            // No ring: the simulated transfer completes immediately, so the IN
            // endpoint is always considered drained.
            true
        }
    }

    /// A bus that simulates a depth-N ring: the per-packet `write` accepts up to
    /// `depth` packets (returning `Ok(len)`) then returns `WouldBlock`, mimicking
    /// the imxrt-usbd ring filling up. Used to test the Lever B looping pump.
    #[cfg(feature = "ring")]
    struct RingBus {
        depth: usize,
        primed: core::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "ring")]
    impl UsbBus for RingBus {
        fn alloc_ep(
            &mut self,
            _d: UsbDirection,
            _a: Option<EndpointAddress>,
            _t: EndpointType,
            _m: u16,
            _i: u8,
        ) -> usb_device::Result<EndpointAddress> {
            Ok(EndpointAddress::from(0))
        }
        fn enable(&mut self) {}
        fn reset(&self) {}
        fn set_device_address(&self, _a: u8) {}
        fn write(&self, _ep: EndpointAddress, buf: &[u8]) -> usb_device::Result<usize> {
            let current = self.primed.load(core::sync::atomic::Ordering::Relaxed);
            if current >= self.depth {
                return Err(UsbError::WouldBlock);
            }
            self.primed
                .store(current + 1, core::sync::atomic::Ordering::Relaxed);
            Ok(buf.len())
        }
        fn read(&self, _ep: EndpointAddress, _buf: &mut [u8]) -> usb_device::Result<usize> {
            Err(UsbError::WouldBlock)
        }
        fn set_stalled(&self, _e: EndpointAddress, _s: bool) {}
        fn is_stalled(&self, _e: EndpointAddress) -> bool {
            false
        }
        fn suspend(&self) {}
        fn resume(&self) {}
        fn poll(&self) -> PollResult {
            PollResult::None
        }
    }

    /// The Lever B ring pump must drain up to `depth` packets per poll (until the
    /// simulated ring reports `WouldBlock`), decrementing residue by exactly the
    /// bytes sent, rather than sending a single packet like the stock path.
    #[cfg(feature = "ring")]
    #[test]
    fn ring_pump_drains_until_wouldblock() {
        use usb_device::device::{UsbDeviceBuilder, UsbVidPid};

        const DEPTH: usize = 8;
        const MPS: usize = 512;
        const BUF: usize = DEPTH * MPS; // IO buffer holds a full ring's worth

        let alloc = UsbBusAllocator::new(RingBus {
            depth: DEPTH,
            primed: core::sync::atomic::AtomicUsize::new(0),
        });
        let mut bbb = BulkOnly::new(&alloc, MPS as u16, 0, vec![0u8; BUF]).unwrap();
        // Trigger UsbBusAllocator::freeze() so endpoint bus_ptr is non-null.
        let _usb_dev = UsbDeviceBuilder::new(&alloc, UsbVidPid(0x0000, 0x0000)).build();

        bbb.state = DataTransferToHost;
        bbb.cbw.data_transfer_len = (BUF as u32) * 2; // plenty of residue, > one ring
        bbb.buf.write(vec![0xABu8; BUF].as_slice()); // stage a full ring of data

        // One write() drives handle_write_to_host once. The ring pump must send
        // DEPTH packets this single poll (stock would send exactly 1).
        bbb.write().unwrap();

        let sent = (BUF as u32 * 2) - bbb.cbw.data_transfer_len;
        assert_eq!(
            (DEPTH * MPS) as u32,
            sent,
            "ring pump must send DEPTH packets per poll, not one"
        );
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

    /// Verify that `bulk_write_data` has non-blocking semantics:
    ///
    /// - Call 1: primes the transfer, returns `WouldBlock`.
    /// - Call 2: polls completion, returns `Ok(512)` and decrements the residue.
    ///
    /// Also confirms that the eventual CSW carries residue == 0.
    #[test]
    fn bulk_write_data_reports_count_and_decrements_residue() {
        const DATA_LEN: usize = 512;

        let alloc = UsbBusAllocator::new(DummyBus);
        let mut bbb = BulkOnly::new(&alloc, 64, 0, vec![0u8; 1024]).unwrap();

        // Manually place the transport in the IN data-transfer state with a
        // 512-byte residue (mimics what start_data_transfer does after a CBW).
        bbb.state = DataTransferToHost;
        bbb.cbw.data_transfer_len = DATA_LEN as u32;

        let src = vec![0xAAu8; DATA_LEN];
        let bus = DummyBus;

        // First call: primes the transfer — must return WouldBlock.
        let first = bbb.bulk_write_data(&bus, &src);
        assert!(
            matches!(first, Err(TransportError::Usb(UsbError::WouldBlock))),
            "first call must return WouldBlock (transfer primed, not yet complete)"
        );
        assert_eq!(
            DATA_LEN as u32, bbb.cbw.data_transfer_len,
            "residue must not change after priming"
        );

        // Second call: polls completion — DummyBus::bulk_poll returns Some(512).
        let count = bbb.bulk_write_data(&bus, &src).unwrap();

        assert_eq!(
            DATA_LEN, count,
            "bulk_write_data must return the byte count"
        );
        assert_eq!(
            0, bbb.cbw.data_transfer_len,
            "residue must reach zero after a full transfer"
        );

        // Confirm the eventual CSW would carry residue == 0 (Passed status).
        bbb.set_status(CommandStatus::Passed);
        let csw_bytes = bbb.build_csw().expect("CSW must be built after set_status");
        let csw_residue = u32::from_le_bytes(csw_bytes[8..12].try_into().unwrap());
        assert_eq!(0, csw_residue, "CSW residue must be 0 after full transfer");
    }
}
