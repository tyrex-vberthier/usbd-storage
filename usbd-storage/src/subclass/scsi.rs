//! USB SCSI

use crate::CLASS_MASS_STORAGE;
use crate::transport::Transport;
#[cfg(feature = "uas")]
use crate::transport::uas::Uas;
use core::fmt::Debug;
use num_enum::TryFromPrimitive;
use usb_device::bus::InterfaceNumber;
use usb_device::bus::UsbBus;
use usb_device::class::{ControlIn, ControlOut, UsbClass};
use usb_device::descriptor::DescriptorWriter;
#[cfg(feature = "uas")]
use usb_device::endpoint::EndpointAddress;
#[cfg(feature = "bbb")]
use {
    crate::fmt::debug,
    crate::subclass::Command,
    crate::transport::TransportError,
    crate::transport::bbb::{BulkOnly, BulkOnlyError},
    core::borrow::BorrowMut,
    usb_device::UsbError,
    usb_device::bus::UsbBusAllocator,
};

/// SCSI device subclass code
pub const SUBCLASS_SCSI: u8 = 0x06; // SCSI Transparent command set

/* SCSI codes */

/* SPC */
const TEST_UNIT_READY: u8 = 0x00;
const REQUEST_SENSE: u8 = 0x03;
const INQUIRY: u8 = 0x12;
const MODE_SENSE_6: u8 = 0x1A;
const MODE_SENSE_10: u8 = 0x5A;

/* SBC */
const READ_10: u8 = 0x28;
#[cfg(feature = "extended_addressing")]
const READ_16: u8 = 0x88;
const READ_CAPACITY_10: u8 = 0x25;
const READ_CAPACITY_16: u8 = 0x9E;
const WRITE_10: u8 = 0x2A;
#[cfg(feature = "extended_addressing")]
const WRITE_16: u8 = 0x8A;

/* MMC */
const READ_FORMAT_CAPACITIES: u8 = 0x23;

/// SCSI command
///
/// Refer to specifications (SPC,SAM,SBC,MMC,etc.)
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum ScsiCommand {
    Unknown {
        cmd: u8,
    },

    /* SPC */
    Inquiry {
        evpd: bool,
        page_code: u8,
        alloc_len: u16,
    },
    TestUnitReady,
    RequestSense {
        desc: bool,
        alloc_len: u8,
    },
    ModeSense6 {
        dbd: bool,
        page_control: PageControl,
        page_code: u8,
        subpage_code: u8,
        alloc_len: u8,
    },
    ModeSense10 {
        dbd: bool,
        page_control: PageControl,
        page_code: u8,
        subpage_code: u8,
        alloc_len: u16,
    },

    /* SBC */
    ReadCapacity10,
    ReadCapacity16 {
        alloc_len: u32,
    },
    Read {
        #[cfg(feature = "extended_addressing")]
        lba: u64,
        #[cfg(feature = "extended_addressing")]
        len: u32,

        #[cfg(not(feature = "extended_addressing"))]
        lba: u32,
        #[cfg(not(feature = "extended_addressing"))]
        len: u16,
    },
    Write {
        #[cfg(feature = "extended_addressing")]
        lba: u64,
        #[cfg(feature = "extended_addressing")]
        len: u32,

        #[cfg(not(feature = "extended_addressing"))]
        lba: u32,
        #[cfg(not(feature = "extended_addressing"))]
        len: u16,
    },

    /* MMC */
    ReadFormatCapacities {
        alloc_len: u16,
    },
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PageControl {
    CurrentValues = 0b00,
    ChangeableValues = 0b01,
    DefaultValues = 0b10,
    SavedValues = 0b11,
}

#[allow(dead_code)]
pub(crate) fn parse_cb(cb: &[u8]) -> ScsiCommand {
    debug_assert!(!cb.is_empty());

    match (cb[0], cb.len()) {
        (TEST_UNIT_READY, _) => ScsiCommand::TestUnitReady,
        (INQUIRY, 5..) => ScsiCommand::Inquiry {
            evpd: (cb[1] & 0b00000001) != 0,
            page_code: cb[2],
            alloc_len: u16::from_be_bytes([cb[3], cb[4]]),
        },
        (REQUEST_SENSE, 5..) => ScsiCommand::RequestSense {
            desc: (cb[1] & 0b00000001) != 0,
            alloc_len: cb[4],
        },
        (READ_CAPACITY_10, _) => ScsiCommand::ReadCapacity10,
        (READ_CAPACITY_16, 14..) => ScsiCommand::ReadCapacity16 {
            alloc_len: u32::from_be_bytes([cb[10], cb[11], cb[12], cb[13]]),
        },
        (READ_10, 9..) => ScsiCommand::Read {
            #[cfg(not(feature = "extended_addressing"))]
            lba: u32::from_be_bytes([cb[2], cb[3], cb[4], cb[5]]),
            #[cfg(not(feature = "extended_addressing"))]
            len: u16::from_be_bytes([cb[7], cb[8]]),

            #[cfg(feature = "extended_addressing")]
            lba: u32::from_be_bytes([cb[2], cb[3], cb[4], cb[5]]) as u64,
            #[cfg(feature = "extended_addressing")]
            len: u16::from_be_bytes([cb[7], cb[8]]) as u32,
        },
        #[cfg(feature = "extended_addressing")]
        (READ_16, 14..) => ScsiCommand::Read {
            lba: u64::from_be_bytes([cb[2], cb[3], cb[4], cb[5], cb[6], cb[7], cb[8], cb[9]]),
            len: u32::from_be_bytes([cb[10], cb[11], cb[12], cb[13]]),
        },
        (WRITE_10, 9..) => ScsiCommand::Write {
            #[cfg(not(feature = "extended_addressing"))]
            lba: u32::from_be_bytes([cb[2], cb[3], cb[4], cb[5]]),
            #[cfg(not(feature = "extended_addressing"))]
            len: u16::from_be_bytes([cb[7], cb[8]]),

            #[cfg(feature = "extended_addressing")]
            lba: u32::from_be_bytes([cb[2], cb[3], cb[4], cb[5]]) as u64,
            #[cfg(feature = "extended_addressing")]
            len: u16::from_be_bytes([cb[7], cb[8]]) as u32,
        },
        #[cfg(feature = "extended_addressing")]
        (WRITE_16, 14..) => ScsiCommand::Write {
            lba: u64::from_be_bytes([cb[2], cb[3], cb[4], cb[5], cb[6], cb[7], cb[8], cb[9]]),
            len: u32::from_be_bytes([cb[10], cb[11], cb[12], cb[13]]),
        },
        (MODE_SENSE_6, 5..) => ScsiCommand::ModeSense6 {
            dbd: (cb[1] & 0b00001000) != 0,
            page_control: PageControl::try_from_primitive(cb[2] >> 6)
                .unwrap_or(PageControl::CurrentValues),
            page_code: cb[2] & 0b00111111,
            subpage_code: cb[3],
            alloc_len: cb[4],
        },
        (MODE_SENSE_10, 9..) => ScsiCommand::ModeSense10 {
            dbd: (cb[1] & 0b00001000) != 0,
            page_control: PageControl::try_from_primitive(cb[2] >> 6)
                .unwrap_or(PageControl::CurrentValues),
            page_code: cb[2] & 0b00111111,
            subpage_code: cb[3],
            alloc_len: u16::from_be_bytes([cb[7], cb[8]]),
        },
        (READ_FORMAT_CAPACITIES, 9..) => ScsiCommand::ReadFormatCapacities {
            alloc_len: u16::from_be_bytes([cb[7], cb[8]]),
        },
        (cmd, _) => ScsiCommand::Unknown { cmd },
    }
}

/// SCSI USB Mass Storage subclass
pub struct Scsi<T: Transport> {
    interface: InterfaceNumber,
    pub(crate) transport: T,
}

/// SCSI subclass implementation with [Bulk Only Transport]
///
/// [Bulk Only Transport]: crate::transport::bbb::BulkOnly
#[cfg(feature = "bbb")]
impl<'alloc, Bus: UsbBus + 'alloc, Buf: BorrowMut<[u8]>> Scsi<BulkOnly<'alloc, Bus, Buf>> {
    /// Creates an SCSI over Bulk Only Transport instance
    ///
    /// # Arguments
    /// * `alloc` - [UsbBusAllocator]
    /// * `packet_size` - Maximum USB packet size. Allowed values: 8,16,32,64
    /// * `max_lun` - The max index of the Logical Unit
    /// * `buf` - The underlying IO buffer. It is **required** to fit at least a `CBW` and/or a single
    ///   packet. It is **recommended** that buffer fits at least one sector
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
    ) -> Result<Self, BulkOnlyError> {
        BulkOnly::new(alloc, packet_size, max_lun, buf).map(|transport| Self {
            interface: alloc.interface(),
            transport,
        })
    }

    /// Drive subclass in both directions
    ///
    /// The passed closure may or may not be called after each time this function is called.
    /// Moreover, it may be called multiple times, if subclass is unable to proceed further.
    ///
    /// # Arguments
    /// * `callback` - closure, in which the SCSI command is processed
    pub fn poll<F>(&mut self, callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>),
    {
        self.poll_inner(
            // pre-read: drive the per-packet OUT path unconditionally.
            |t| t.read(),
            // write step: the ordinary transport write.
            |t| t.write(),
            // post-read: drive the per-packet OUT path unconditionally.
            |t| t.read(),
            // command callback.
            callback,
        )
    }
}

/// SCSI subclass implementation with [Bulk Only Transport] — `transfer` feature extension
///
/// [Bulk Only Transport]: crate::transport::bbb::BulkOnly
#[cfg(all(feature = "bbb", feature = "transfer"))]
impl<'alloc, Bus, Buf> Scsi<BulkOnly<'alloc, Bus, Buf>>
where
    Bus: UsbBus + crate::transfer::TransferBus + 'alloc,
    Buf: BorrowMut<[u8]>,
{
    /// Transfer-based poll: per-packet CBW/CSW/SPC, zero-copy bulk data phases
    /// driven by the callback through
    /// [`Command::read_data_transfer`] / [`Command::write_data_transfer`].
    ///
    /// During the OUT (host→device) data phase the callback owns the OUT
    /// endpoint via a single large transfer.  The per-packet `read()` path is
    /// skipped while that transfer is in flight so it cannot collide with the
    /// zero-copy prime.  The IN data phase and CBW/CSW phases use the normal
    /// per-packet path.
    pub fn poll_transfer<F>(&mut self, bus: &Bus, mut callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>, &Bus),
    {
        self.poll_inner(
            // Pre-read: skip the per-packet OUT read while the callback's zero-copy
            // OUT transfer owns the endpoint (no-swallow rule).
            |t| {
                if t.is_data_transfer_phase() {
                    Ok(())
                } else {
                    t.read()
                }
            },
            // Write: ordinary per-packet IN / CSW path.  The transfer_phase guard
            // inside write() handles the zero-copy IN case automatically.
            |t| t.write(),
            // Post-read: advance the OUT data phase to StatusTransfer once the
            // callback has set a status, WITHOUT a colliding per-packet read.
            |t| {
                if t.is_data_transfer_phase() {
                    t.finish_data_transfer_phase()
                } else {
                    t.read()
                }
            },
            // Callback adapter: Command mutably borrows the transport; the bus
            // is passed separately so the callback can call read/write_data_transfer.
            |cmd| callback(cmd, bus),
        )
    }
}

/// Shared, panic-free `Result`-collapse used by `poll_inner`.
///
/// `WouldBlock` and any transport-level `Error(_)` are non-fatal (the next
/// poll retries); only a genuine non-`WouldBlock` USB error is propagated.
#[cfg(feature = "bbb")]
fn map_ignore<T>(res: Result<T, TransportError<BulkOnlyError>>) -> Result<(), UsbError> {
    match res {
        Ok(_) | Err(TransportError::Usb(UsbError::WouldBlock)) | Err(TransportError::Error(_)) => {
            Ok(())
        }
        Err(TransportError::Usb(err)) => Err(err),
    }
}

#[cfg(feature = "bbb")]
impl<'alloc, Bus: UsbBus + 'alloc, Buf: BorrowMut<[u8]>> Scsi<BulkOnly<'alloc, Bus, Buf>> {
    /// Common poll skeleton. The three transport steps and the user callback are
    /// supplied as closures so callers can vary them without duplicating the
    /// dispatch logic:
    ///
    /// * `pre_read`  — drive the inbound (OUT) path before the user action.
    /// * `write`     — drive the outbound (IN/CSW) path.
    /// * `post_read` — drive the inbound path after the user action.
    #[inline]
    fn poll_inner<PreRead, Write, PostRead, Cb>(
        &mut self,
        mut pre_read: PreRead,
        mut write: Write,
        mut post_read: PostRead,
        mut callback: Cb,
    ) -> Result<(), UsbError>
    where
        PreRead:
            FnMut(&mut BulkOnly<'alloc, Bus, Buf>) -> Result<(), TransportError<BulkOnlyError>>,
        Write: FnMut(&mut BulkOnly<'alloc, Bus, Buf>) -> Result<(), TransportError<BulkOnlyError>>,
        PostRead:
            FnMut(&mut BulkOnly<'alloc, Bus, Buf>) -> Result<(), TransportError<BulkOnlyError>>,
        Cb: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>),
    {
        // drive transport in both directions before user action
        map_ignore(pre_read(&mut self.transport))?;
        map_ignore(write(&mut self.transport))?;

        if let Some(raw_cb) = self.transport.get_command() {
            // exec callback only if user action required
            if !self.transport.has_status() {
                let lun = raw_cb.lun;
                let kind = parse_cb(raw_cb.bytes);

                debug!("usb: scsi: Command: {}", kind);

                loop {
                    callback(Command {
                        class: self,
                        kind,
                        lun,
                    });

                    // drive transport in both directions after user action.
                    // exec callback if not enough data
                    match write(&mut self.transport) {
                        Err(TransportError::Error(BulkOnlyError::FullPacketExpected)) => {
                            continue;
                        }
                        Ok(_)
                        | Err(TransportError::Error(_))
                        | Err(TransportError::Usb(UsbError::WouldBlock)) => { /* ignore */ }
                        Err(TransportError::Usb(err)) => {
                            return Err(err);
                        }
                    };
                    map_ignore(post_read(&mut self.transport))?;

                    break;
                }
            }
        }

        Ok(())
    }
}

impl<Bus, T> UsbClass<Bus> for Scsi<T>
where
    Bus: UsbBus,
    T: Transport<Bus = Bus>,
{
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        writer.iad(
            self.interface,
            1,
            CLASS_MASS_STORAGE,
            SUBCLASS_SCSI,
            T::PROTO,
            None,
        )?;
        writer.interface(self.interface, CLASS_MASS_STORAGE, SUBCLASS_SCSI, T::PROTO)?;

        self.transport.get_endpoint_descriptors(writer)?;

        Ok(())
    }

    fn reset(&mut self) {
        self.transport.reset()
    }

    fn control_in(&mut self, xfer: ControlIn<Bus>) {
        self.transport.control_in(xfer)
    }

    fn control_out(&mut self, xfer: ControlOut<Bus>) {
        self.transport.control_out(xfer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cb_short_inquiry_does_not_panic() {
        // INQUIRY opcode but no operands present.
        assert!(matches!(
            parse_cb(&[INQUIRY]),
            ScsiCommand::Unknown { cmd } if cmd == INQUIRY
        ));
    }

    #[test]
    fn parse_cb_short_read10_does_not_panic() {
        // READ_10 needs bytes up to index 8; give it only the opcode.
        assert!(matches!(
            parse_cb(&[READ_10]),
            ScsiCommand::Unknown { cmd } if cmd == READ_10
        ));
    }

    #[test]
    fn parse_cb_short_read_capacity_16_does_not_panic() {
        // READ_CAPACITY_16 reads cb[10..14]; a 10-byte CDB is too short.
        let cb = [READ_CAPACITY_16, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            parse_cb(&cb),
            ScsiCommand::Unknown { cmd } if cmd == READ_CAPACITY_16
        ));
    }

    #[cfg(feature = "extended_addressing")]
    #[test]
    fn parse_cb_short_read16_yields_unknown_not_panic() {
        // READ_16 (0x88) with a CDB shorter than 14 bytes used to index past
        // the slice and panic. It must yield the Unknown path instead.
        let cb = [READ_16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 12 bytes < 14
        assert!(matches!(
            parse_cb(&cb),
            ScsiCommand::Unknown { cmd } if cmd == READ_16
        ));
    }

    #[cfg(feature = "extended_addressing")]
    #[test]
    fn parse_cb_short_write16_yields_unknown_not_panic() {
        let cb = [WRITE_16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 13 bytes < 14
        assert!(matches!(
            parse_cb(&cb),
            ScsiCommand::Unknown { cmd } if cmd == WRITE_16
        ));
    }

    #[cfg(feature = "extended_addressing")]
    #[test]
    fn parse_cb_full_read16_parses() {
        // A full 16-byte READ_16: opcode + 8-byte LBA + 4-byte length.
        let mut cb = [0u8; 16];
        cb[0] = READ_16;
        cb[9] = 0x01; // LBA low byte
        cb[13] = 0x08; // transfer length
        match parse_cb(&cb) {
            ScsiCommand::Read { lba, len } => {
                assert_eq!(lba, 1);
                assert_eq!(len, 8);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn parse_cb_mode_sense_6_page_control_does_not_panic() {
        // page_control = cb[2] >> 6; all four 2-bit values are valid, and a
        // too-short CDB yields Unknown rather than panicking on an unwrap.
        let cb = [MODE_SENSE_6, 0, 0b1100_0000, 0, 0];
        match parse_cb(&cb) {
            ScsiCommand::ModeSense6 { page_control, .. } => {
                assert!(matches!(page_control, PageControl::SavedValues));
            }
            other => panic!("expected ModeSense6, got {other:?}"),
        }
        assert!(matches!(
            parse_cb(&[MODE_SENSE_6]),
            ScsiCommand::Unknown { cmd } if cmd == MODE_SENSE_6
        ));
    }
}

// ---------------------------------------------------------------------------
// ScsiUas — SCSI over UAS (alt-setting 1) with BOT fall-back (alt-setting 0)
// ---------------------------------------------------------------------------

/// SCSI Mass Storage class that exposes both BOT (alt 0) and UAS (alt 1).
///
/// Internally the BOT transport (`inner`) owns the two shared data endpoints
/// (bulk IN / bulk OUT); the UAS engine (`uas`) owns two additional bulk
/// endpoints (command OUT / status IN) and stores the shared endpoint addresses
/// so data-phase transfers can be driven on them.
///
/// # Alternate setting behaviour
///
/// * **Alt 0 (BOT)** — `poll_transfer` is forwarded to the inner `Scsi`; the
///   UAS engine is idle.
/// * **Alt 1 (UAS)** — `poll_transfer` is a no-op; the caller drives the UAS
///   engine via `uas()` directly.
///
/// SET_INTERFACE switches between the two settings; both the BOT state machine
/// and the UAS engine are reset on every switch.
#[cfg(feature = "uas")]
pub struct ScsiUas<'alloc, Bus: UsbBus, Buf: BorrowMut<[u8]>> {
    /// BOT-based SCSI class (owns the shared data endpoints).
    inner: Scsi<BulkOnly<'alloc, Bus, Buf>>,
    /// UAS engine (owns command/status endpoints; references shared data EPs).
    uas: Uas<'alloc, Bus>,
    /// Currently active alternate setting: 0 = BOT, 1 = UAS.
    active_alt: u8,
}

#[cfg(feature = "uas")]
impl<'alloc, Bus, Buf> ScsiUas<'alloc, Bus, Buf>
where
    Bus: UsbBus + crate::transfer::TransferBus + 'alloc,
    Buf: BorrowMut<[u8]>,
{
    /// Construct a `ScsiUas` instance.
    ///
    /// The BOT transport is allocated first (so the shared data endpoints get
    /// their deterministic addresses), then the UAS engine is allocated with
    /// those addresses.
    ///
    /// # Arguments
    ///
    /// * `alloc` — USB bus allocator.
    /// * `packet_size` — Maximum USB packet size (512 for High Speed).
    /// * `max_lun` — Maximum LUN index (0 for single-LUN devices).
    /// * `buf` — IO buffer for the BOT transport; must fit at least one CBW
    ///   and one full packet.
    ///
    /// # Errors
    ///
    /// Returns a [`BulkOnlyError`] if the BOT transport cannot be constructed
    /// (invalid `max_lun` or buffer too small).
    ///
    /// # Panics
    ///
    /// Panics if endpoint allocation fails (same contract as
    /// [`Scsi::new`]).
    pub fn new(
        alloc: &'alloc UsbBusAllocator<Bus>,
        packet_size: u16,
        max_lun: u8,
        buf: Buf,
    ) -> Result<Self, BulkOnlyError> {
        let inner = Scsi::new(alloc, packet_size, max_lun, buf)?;
        // Retrieve the shared data endpoint addresses from the BOT transport
        // before handing control to the UAS engine.
        let (data_in_ep, data_out_ep) = inner.transport.data_endpoints();
        let data_in = data_in_ep.address();
        let data_out = data_out_ep.address();
        let uas = Uas::new(alloc, packet_size, data_in, data_out);
        Ok(Self {
            inner,
            uas,
            active_alt: 0,
        })
    }

    /// Drive the BOT data path (active only in alt 0).
    ///
    /// When alt 1 (UAS) is active this is a no-op; the caller drives the UAS
    /// engine directly via [`Self::uas`].
    ///
    /// See [`Scsi::poll_transfer`] for the callback contract.
    pub fn poll_transfer<F>(&mut self, bus: &Bus, callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>, &Bus),
    {
        if self.active_alt == 0 {
            self.inner.poll_transfer(bus, callback)
        } else {
            Ok(())
        }
    }

    /// Return the currently active alternate setting (0 = BOT, 1 = UAS).
    pub fn active_alt(&self) -> u8 {
        self.active_alt
    }

    /// Return a mutable reference to the UAS engine.
    ///
    /// Use this to call [`Uas::pump`], [`Uas::enqueue_status`], and the data
    /// pipe helpers when alt 1 is active.
    pub fn uas(&mut self) -> &mut Uas<'alloc, Bus> {
        &mut self.uas
    }

    /// Addresses of the shared data pipes as `(bulk IN, bulk OUT)`.
    ///
    /// These endpoints are listed in BOTH alternate settings; on a
    /// SET_INTERFACE switch the firmware must cancel any transfers the
    /// previous alt left queued on them (a stale BOT CBW prime on the bulk
    /// OUT otherwise swallows the first packet of the first UAS data-out
    /// phase — HW-observed 2026-06-11).
    pub fn data_pipe_addresses(&self) -> (EndpointAddress, EndpointAddress) {
        let (data_in, data_out) = self.inner.transport.data_endpoints();
        (data_in.address(), data_out.address())
    }
}

/// `UsbClass` implementation for [`ScsiUas`].
///
/// Descriptors mirror `Scsi<BulkOnly>`'s alt-0 output byte-for-byte, then
/// append the alt-1 UAS descriptor set in f_tcm HS order
/// (data-in + PU3, data-out + PU4, status + PU2, cmd + PU1).
///
/// Control requests and endpoint callbacks are forwarded to the inner BOT
/// class so GET_MAX_LUN and BOT Mass Storage Reset keep working under alt 0.
///
/// GET_INTERFACE / SET_INTERFACE are handled here:
/// * `get_alt_setting` returns `Some(active_alt)` for the MSC interface.
/// * `set_alt_setting` accepts 0 and 1; on accept it resets both the BOT state
///   machine and the UAS engine and returns `true`.
#[cfg(feature = "uas")]
impl<'alloc, Bus, Buf> UsbClass<Bus> for ScsiUas<'alloc, Bus, Buf>
where
    Bus: UsbBus + crate::transfer::TransferBus + 'alloc,
    Buf: BorrowMut<[u8]>,
{
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        use crate::transport::bbb::TRANSPORT_BBB;
        use crate::transport::uas::TRANSPORT_UAS;

        // --- Alt 0: BOT (byte-identical to Scsi<BulkOnly>'s output) ----------
        //
        // Scsi<T>::UsbClass writes: IAD, interface(alt 0), endpoint descriptors.
        // We reproduce this exactly so the alt-0 wire encoding is unchanged.
        writer.iad(
            self.inner.interface,
            1,
            CLASS_MASS_STORAGE,
            SUBCLASS_SCSI,
            TRANSPORT_BBB,
            None,
        )?;
        writer.interface(
            self.inner.interface,
            CLASS_MASS_STORAGE,
            SUBCLASS_SCSI,
            TRANSPORT_BBB,
        )?;
        // BOT endpoints: in_ep (bulk IN), out_ep (bulk OUT).
        self.inner.transport.get_endpoint_descriptors(writer)?;

        // --- Alt 1: UAS, f_tcm HS order: data-in, data-out, status, cmd ------
        //
        // Each endpoint is immediately followed by its 4-byte Pipe Usage
        // descriptor (type 0x24).  The actual writes are delegated to
        // `Uas::write_alt1_descriptors` which has access to the private
        // status/command endpoint fields.
        writer.interface_alt(
            self.inner.interface,
            1,
            CLASS_MASS_STORAGE,
            SUBCLASS_SCSI,
            TRANSPORT_UAS,
            None,
        )?;

        let (data_in_ep, data_out_ep) = self.inner.transport.data_endpoints();
        self.uas
            .write_alt1_descriptors(writer, data_in_ep, data_out_ep)?;

        Ok(())
    }

    fn reset(&mut self) {
        self.inner.transport.reset();
        self.uas.reset();
        self.active_alt = 0;
    }

    fn control_in(&mut self, xfer: ControlIn<Bus>) {
        // Forward BOT class requests (GET_MAX_LUN, BOT reset) to the inner
        // transport so they keep working while alt 0 is active.
        self.inner.transport.control_in(xfer);
    }

    fn get_alt_setting(&mut self, interface: InterfaceNumber) -> Option<u8> {
        if interface == self.inner.interface {
            Some(self.active_alt)
        } else {
            None
        }
    }

    fn set_alt_setting(&mut self, interface: InterfaceNumber, alternative: u8) -> bool {
        if interface != self.inner.interface {
            return false;
        }
        if alternative > 1 {
            return false;
        }
        // Accept: reset both transports and record the new setting.
        self.inner.transport.reset();
        self.uas.reset();
        self.active_alt = alternative;
        true
    }
}
