//! USB SCSI

use crate::transport::Transport;
use crate::CLASS_MASS_STORAGE;
use core::fmt::Debug;
use num_enum::TryFromPrimitive;
use usb_device::bus::InterfaceNumber;
use usb_device::bus::UsbBus;
use usb_device::class::{ControlIn, UsbClass};
use usb_device::descriptor::DescriptorWriter;
#[cfg(feature = "bbb")]
use {
    crate::fmt::debug,
    crate::subclass::Command,
    crate::transport::bbb::{BulkOnly, BulkOnlyError},
    crate::transport::TransportError,
    core::borrow::BorrowMut,
    usb_device::bus::UsbBusAllocator,
    usb_device::UsbError,
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
fn parse_cb(cb: &[u8]) -> ScsiCommand {
    // Every command block carries at least its opcode. `cb` is host-supplied
    // (the CBW `block` truncated to `block_len`, validated only to
    // `MIN_CB_LEN..=MAX_CB_LEN`), so an opcode that needs more bytes than are
    // present must NOT index past the slice — that would panic on a malformed
    // CDB. Each arm uses `read_*` helpers that fall back to the
    // `ScsiCommand::Unknown` path when the CDB is too short for that opcode.
    let opcode = match cb.first() {
        Some(&opcode) => opcode,
        None => return ScsiCommand::Unknown { cmd: 0 },
    };

    /// Fetch a single CDB byte, or signal "too short".
    fn byte(cb: &[u8], i: usize) -> Option<u8> {
        cb.get(i).copied()
    }

    fn be_u16(cb: &[u8], i: usize) -> Option<u16> {
        cb.get(i..i + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }

    fn be_u32(cb: &[u8], i: usize) -> Option<u32> {
        cb.get(i..i + 4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    #[cfg(feature = "extended_addressing")]
    fn be_u64(cb: &[u8], i: usize) -> Option<u64> {
        cb.get(i..i + 8)
            .map(|s| u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }

    let unknown = ScsiCommand::Unknown { cmd: opcode };

    match opcode {
        TEST_UNIT_READY => ScsiCommand::TestUnitReady,
        INQUIRY => {
            let (Some(b1), Some(page_code), Some(alloc_len)) =
                (byte(cb, 1), byte(cb, 2), be_u16(cb, 3))
            else {
                return unknown;
            };
            ScsiCommand::Inquiry {
                evpd: (b1 & 0b00000001) != 0,
                page_code,
                alloc_len,
            }
        }
        REQUEST_SENSE => {
            let (Some(b1), Some(alloc_len)) = (byte(cb, 1), byte(cb, 4)) else {
                return unknown;
            };
            ScsiCommand::RequestSense {
                desc: (b1 & 0b00000001) != 0,
                alloc_len,
            }
        }
        READ_CAPACITY_10 => ScsiCommand::ReadCapacity10,
        READ_CAPACITY_16 => {
            let Some(alloc_len) = be_u32(cb, 10) else {
                return unknown;
            };
            ScsiCommand::ReadCapacity16 { alloc_len }
        }
        READ_10 => {
            let (Some(lba), Some(len)) = (be_u32(cb, 2), be_u16(cb, 7)) else {
                return unknown;
            };
            ScsiCommand::Read {
                #[cfg(not(feature = "extended_addressing"))]
                lba,
                #[cfg(not(feature = "extended_addressing"))]
                len,

                #[cfg(feature = "extended_addressing")]
                lba: lba as u64,
                #[cfg(feature = "extended_addressing")]
                len: len as u32,
            }
        }
        #[cfg(feature = "extended_addressing")]
        READ_16 => {
            let (Some(lba), Some(len)) = (be_u64(cb, 2), be_u32(cb, 10)) else {
                return unknown;
            };
            ScsiCommand::Read { lba, len }
        }
        WRITE_10 => {
            let (Some(lba), Some(len)) = (be_u32(cb, 2), be_u16(cb, 7)) else {
                return unknown;
            };
            ScsiCommand::Write {
                #[cfg(not(feature = "extended_addressing"))]
                lba,
                #[cfg(not(feature = "extended_addressing"))]
                len,

                #[cfg(feature = "extended_addressing")]
                lba: lba as u64,
                #[cfg(feature = "extended_addressing")]
                len: len as u32,
            }
        }
        #[cfg(feature = "extended_addressing")]
        WRITE_16 => {
            let (Some(lba), Some(len)) = (be_u64(cb, 2), be_u32(cb, 10)) else {
                return unknown;
            };
            ScsiCommand::Write { lba, len }
        }
        MODE_SENSE_6 => {
            let (Some(b1), Some(b2), Some(subpage_code), Some(alloc_len)) =
                (byte(cb, 1), byte(cb, 2), byte(cb, 3), byte(cb, 4))
            else {
                return unknown;
            };
            ScsiCommand::ModeSense6 {
                dbd: (b1 & 0b00001000) != 0,
                page_control: PageControl::try_from_primitive(b2 >> 6)
                    .unwrap_or(PageControl::CurrentValues),
                page_code: b2 & 0b00111111,
                subpage_code,
                alloc_len,
            }
        }
        MODE_SENSE_10 => {
            let (Some(b1), Some(b2), Some(subpage_code), Some(alloc_len)) =
                (byte(cb, 1), byte(cb, 2), byte(cb, 3), be_u16(cb, 7))
            else {
                return unknown;
            };
            ScsiCommand::ModeSense10 {
                dbd: (b1 & 0b00001000) != 0,
                page_control: PageControl::try_from_primitive(b2 >> 6)
                    .unwrap_or(PageControl::CurrentValues),
                page_code: b2 & 0b00111111,
                subpage_code,
                alloc_len,
            }
        }
        READ_FORMAT_CAPACITIES => {
            let Some(alloc_len) = be_u16(cb, 7) else {
                return unknown;
            };
            ScsiCommand::ReadFormatCapacities { alloc_len }
        }
        cmd => ScsiCommand::Unknown { cmd },
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
            // write step: the ordinary (non-ring) transport write.
            |t| t.write(),
            // post-read: drive the per-packet OUT path unconditionally.
            |t| t.read(),
            // command callback (no bus capability).
            callback,
        )
    }
}

/// Shared, panic-free `Result`-collapse used by every `poll*` variant.
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
    /// Common poll skeleton shared by `poll`, `poll_bulk`, `poll_ring` and
    /// `poll_ring_bulk`. The four variants differ only in three steps, each
    /// supplied as a closure operating on the transport, plus the user
    /// callback (already bound to whatever bus capability it needs):
    ///
    /// * `pre_read`  — drive the inbound (OUT) path before the user action.
    /// * `write`     — drive the outbound (IN/CSW) path; the ring variants pass
    ///   the IN-ring drain state, the bulk variants skip the colliding
    ///   per-packet read elsewhere.
    /// * `post_read` — drive the inbound path after the user action.
    ///
    /// Keeping this in one place means a residue/tag/serialization fix lands in
    /// every variant at once.
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

/// `poll_bulk` — like [`Scsi::poll`] but the callback receives a [`Command`]
/// that also has access to the big-transfer [`Command::bulk_write_data`] /
/// [`Command::bulk_read_data`] helpers.
///
/// Available whenever the bus satisfies both [`UsbBus`] and
/// [`crate::bulk::BulkBus`].  The SPC small-data path in the callback can
/// still use the ordinary [`Command::write_data`] / [`Command::read_data`]
/// / [`Command::try_write_data_all`] helpers — `poll_bulk` only widens the
/// callback's capability; it does not restrict it.
///
/// `Scsi::poll` is left fully intact; use it when the bus does not implement
/// `BulkBus`.
#[cfg(feature = "bbb")]
impl<'alloc, Bus, Buf> Scsi<BulkOnly<'alloc, Bus, Buf>>
where
    Bus: UsbBus + crate::bulk::BulkBus + 'alloc,
    Buf: BorrowMut<[u8]>,
{
    /// Drive subclass in both directions using the bulk fast-path.
    ///
    /// Identical dispatch logic to [`Scsi::poll`]; the difference is that the
    /// bus reference is threaded through to the callback so the READ/WRITE arms
    /// can call [`Command::bulk_write_data`] / [`Command::bulk_read_data`].
    pub fn poll_bulk<F>(&mut self, bus: &Bus, mut callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>, &Bus),
    {
        // During the OUT (host→device) data phase the bulk callback owns the
        // shared OUT endpoint via a single large dTD.  The per-packet
        // `transport.read()` path collides with that prime (it re-primes a
        // 512-byte per-packet OUT transfer on the same endpoint, blocking the
        // bulk prime and stealing the host's data), so skip it in that phase.
        // The IN data phase and the CBW/CSW phases use the normal path.
        self.poll_inner(
            |t| {
                if t.is_bulk_out_phase() {
                    Ok(())
                } else {
                    t.read()
                }
            },
            |t| t.write(),
            // In the OUT data phase, advance to the CSW once the callback has
            // set a status — but WITHOUT a per-packet read (which would collide
            // with the bulk OUT prime).  Otherwise drive the normal read.
            |t| {
                if t.is_bulk_out_phase() {
                    t.finish_bulk_out_phase()
                } else {
                    t.read()
                }
            },
            |cmd| callback(cmd, bus),
        )
    }

    /// Ring-aware **and** bulk-OUT-aware poll. CSW status is serialized against the IN
    /// ring (`write_ring` + `in_ep_drained`, preserving BOT serialization on a multi-TD
    /// bus); the OUT data phase is driven by the callback's `bulk_read_data` (big dTD),
    /// so the colliding per-packet `read()` is skipped while `is_bulk_out_phase()`.
    /// The callback receives the bus so it can call `bulk_read_data`/`bulk_write_data`.
    #[cfg(feature = "ring")]
    pub fn poll_ring_bulk<F>(&mut self, bus: &Bus, mut callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>, &Bus),
    {
        let in_addr = self.transport.in_ep_address();

        self.poll_inner(
            // Skip the colliding per-packet read while the bulk OUT dTD owns
            // the endpoint.
            |t| {
                if t.is_bulk_out_phase() {
                    Ok(())
                } else {
                    t.read()
                }
            },
            // Re-query drain state each pass: the callback may have primed more
            // IN data, changing the ring occupancy.
            |t| t.write_ring(bus.in_ep_drained(in_addr)),
            |t| {
                if t.is_bulk_out_phase() {
                    t.finish_bulk_out_phase()
                } else {
                    t.read()
                }
            },
            |cmd| callback(cmd, bus),
        )
    }

    /// Ring-aware variant of [`Scsi::poll`] for a multi-TD bus.
    ///
    /// Identical dispatch to [`Scsi::poll`], except the CSW status phase is
    /// serialized against the IN ring: before each transport write, the bus is
    /// queried via [`BulkBus::in_ep_drained`] and the result threaded into
    /// [`BulkOnly::write_ring`]. This keeps the IN ring empty at every command
    /// boundary, so the next command's response cannot pipeline ahead of the
    /// current CSW (which the host would read as a stale/duplicate status — a BOT
    /// phase error that resets the device). Within a command's data phase the ring
    /// still pipelines freely. The callback uses the ordinary per-packet
    /// `write_data`/`read_data` helpers.
    ///
    /// [`BulkBus::in_ep_drained`]: crate::bulk::BulkBus::in_ep_drained
    /// [`BulkOnly::write_ring`]: crate::transport::bbb::BulkOnly::write_ring
    #[cfg(feature = "ring")]
    pub fn poll_ring<F>(&mut self, bus: &Bus, callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>),
    {
        let in_addr = self.transport.in_ep_address();

        self.poll_inner(
            // drive the inbound per-packet path before user action
            |t| t.read(),
            // serialize CSW against the IN ring via the drain state; re-queried
            // each pass since the callback may have primed more IN data.
            |t| t.write_ring(bus.in_ep_drained(in_addr)),
            |t| t.read(),
            callback,
        )
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cb_empty_is_unknown() {
        assert!(matches!(parse_cb(&[]), ScsiCommand::Unknown { cmd: 0 }));
    }

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
        // the slice and panic. It must now yield the Unknown path.
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
        // too-short CDB yields Unknown rather than panicking on the unwrap.
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
