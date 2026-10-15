//! USB Floppy Interface

use crate::CLASS_MASS_STORAGE;
use crate::fmt::trace;
use crate::transport::Transport;
use usb_device::bus::InterfaceNumber;
use usb_device::bus::UsbBus;
use usb_device::class::{ControlIn, UsbClass};
use usb_device::descriptor::DescriptorWriter;

#[cfg(feature = "bbb")]
use {
    crate::fmt::debug,
    crate::subclass::Command,
    crate::transport::TransportError,
    crate::transport::bbb::{BulkOnly, BulkOnlyError},
    core::borrow::BorrowMut,
    usb_device::bus::UsbBusAllocator,
};

/// UFI device subclass code
pub const SUBCLASS_UFI: u8 = 0x04; // UFI command set

/* UFI codes */
const FORMAT_UNIT: u8 = 0x04;
const INQUIRY: u8 = 0x12;
const MODE_SELECT: u8 = 0x55;
const MODE_SENSE: u8 = 0x5A;
const PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;
const READ_10: u8 = 0x28;
const READ_12: u8 = 0xA8;
const READ_CAPACITY: u8 = 0x25;
const READ_FORMAT_CAPACITIES: u8 = 0x23;
const REQUEST_SENSE: u8 = 0x03;
const REZERO_UNIT: u8 = 0x01;
const SEEK_10: u8 = 0x2B;
const SEND_DIAGNOSTIC: u8 = 0x1D;
const START_STOP: u8 = 0x1B;
const TEST_UNIT_READY: u8 = 0x00;
const VERIFY: u8 = 0x2F;
const WRITE_10: u8 = 0x2A;
const WRITE_12: u8 = 0xAA;
const WRITE_AND_VERIFY: u8 = 0x2E;

pub fn lba_to_sector(lba: u32, sec_trk: u8) -> u32 {
    lba % sec_trk as u32 + 1
}

pub fn lba_to_head(lba: u32, sec_trk: u8, head_trk: u8) -> u32 {
    (lba / sec_trk as u32) % head_trk as u32
}

pub fn lba_to_track(lba: u32, sec_trk: u8, head_trk: u8) -> u32 {
    (lba / sec_trk as u32) / head_trk as u32
}

/// UFI command
///
/// Refer to specification
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum UfiCommand {
    Unknown,

    FormatUnit {
        track: u8,
        parameter_list_len: u16,
    },

    Inquiry {
        alloc_len: u8,
    },

    TestUnitReady,

    PreventAllowMediumRemoval {
        prevent: bool,
    },

    ReadCapacity,

    RequestSense {
        alloc_len: u8,
    },

    ModeSense {
        page_control: u8,
        page_code: u8,
        param_list_len: u16,
    },

    ModeSelect {
        parameter_list_len: u16,
    },

    StartStop {
        start: bool,
        eject: bool,
    },

    Read {
        lba: u32,
        len: u32,
    },

    Write {
        lba: u32,
        len: u32,
        verify: bool,
    },

    ReadFormatCapacities {
        alloc_len: u16,
    },

    RezeroUnit,

    Seek {
        lba: u32,
    },

    SendDiagnostic {
        default: bool,
    },

    Verify {
        lba: u32,
        len: u16,
    },
}

#[allow(dead_code)]
fn parse_cb(cb: &[u8]) -> UfiCommand {
    let Some(&opcode) = cb.first() else {
        return UfiCommand::Unknown;
    };
    // Each arm names the shortest command block that carries the fields it reads, so the
    // indexing below stays in bounds; anything shorter is an unknown command.
    let be16 = |at: usize| u16::from_be_bytes([cb[at], cb[at + 1]]);
    let be32 = |at: usize| u32::from_be_bytes([cb[at], cb[at + 1], cb[at + 2], cb[at + 3]]);
    match (opcode, cb.len()) {
        (REQUEST_SENSE, 5..) => UfiCommand::RequestSense { alloc_len: cb[4] },
        (INQUIRY, 5..) => UfiCommand::Inquiry { alloc_len: cb[4] },
        (TEST_UNIT_READY, _) => UfiCommand::TestUnitReady,
        (READ_CAPACITY, _) => UfiCommand::ReadCapacity,
        (PREVENT_ALLOW_MEDIUM_REMOVAL, 5..) => UfiCommand::PreventAllowMediumRemoval {
            prevent: cb[4] != 0,
        },
        (MODE_SENSE, 9..) => UfiCommand::ModeSense {
            page_control: cb[2] >> 6,
            page_code: cb[2] & 0b00111111,
            param_list_len: be16(7),
        },
        (READ_10, 9..) => UfiCommand::Read {
            lba: be32(2),
            len: u32::from(be16(7)),
        },
        (READ_12, 10..) => UfiCommand::Read {
            lba: be32(2),
            len: be32(6),
        },
        (WRITE_10, 9..) => UfiCommand::Write {
            lba: be32(2),
            len: u32::from(be16(7)),
            verify: false,
        },
        (WRITE_12, 10..) => UfiCommand::Write {
            lba: be32(2),
            len: be32(6),
            verify: false,
        },
        (WRITE_AND_VERIFY, 9..) => UfiCommand::Write {
            lba: be32(2),
            len: u32::from(be16(7)),
            verify: true,
        },
        (FORMAT_UNIT, 9..) => UfiCommand::FormatUnit {
            track: cb[2],
            parameter_list_len: be16(7),
        },
        (MODE_SELECT, 9..) => UfiCommand::ModeSelect {
            parameter_list_len: be16(7),
        },
        (READ_FORMAT_CAPACITIES, 9..) => UfiCommand::ReadFormatCapacities { alloc_len: be16(7) },
        (REZERO_UNIT, _) => UfiCommand::RezeroUnit,
        (SEEK_10, 6..) => UfiCommand::Seek { lba: be32(2) },
        (SEND_DIAGNOSTIC, 2..) => UfiCommand::SendDiagnostic {
            default: cb[1] & 1 << 2 > 0,
        },
        (START_STOP, 5..) => UfiCommand::StartStop {
            start: cb[4] & 1 > 0,
            eject: cb[4] == 2,
        },
        (VERIFY, 9..) => UfiCommand::Verify {
            lba: be32(2),
            len: be16(7),
        },
        _ => UfiCommand::Unknown,
    }
}

/// UFI subclass
pub struct Ufi<T: Transport> {
    interface: InterfaceNumber,
    pub(crate) transport: T,
}

/// UFI subclass implementation with [Bulk Only Transport]
///
/// [Bulk Only Transport]: crate::transport::bbb::BulkOnly
#[cfg(feature = "bbb")]
impl<'alloc, Bus: UsbBus + 'alloc, Buf: BorrowMut<[u8]>> Ufi<BulkOnly<'alloc, Bus, Buf>> {
    /// Creates a UFI over Bulk Only Transport instance
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
    /// Panics if endpoint allocation fails.
    ///
    /// [InvalidMaxLun]: crate::transport::bbb::BulkOnlyError::InvalidMaxLun
    /// [BufferTooSmall]: crate::transport::bbb::BulkOnlyError::BufferTooSmall
    /// [UsbBusAllocator]: usb_device::bus::UsbBusAllocator
    pub fn new(
        alloc: &'alloc UsbBusAllocator<Bus>,
        packet_size: u16,
        buf: Buf,
    ) -> Result<Self, BulkOnlyError> {
        BulkOnly::new(alloc, packet_size, 0, buf).map(|transport| Self {
            interface: alloc.interface(),
            transport,
        })
    }

    /// Poll current UFI command
    ///
    /// # Arguments
    /// * `callback` - closure, in which the UFI command is processed. If there
    ///   is no current command available or it doesn't require any input, this
    ///   callback is *not* called.
    pub fn poll_command<F>(&mut self, mut callback: F) -> Result<(), TransportError<BulkOnlyError>>
    where
        F: FnMut(
            Command<UfiCommand, Ufi<BulkOnly<'alloc, Bus, Buf>>>,
        ) -> Result<(), TransportError<BulkOnlyError>>,
    {
        trace!("usb: ufi: poll_command");

        if let Some(raw_cb) = self.transport.get_command() {
            // exec callback only if user action required
            if !self.transport.has_status() {
                let lun = raw_cb.lun;
                let kind = parse_cb(raw_cb.bytes);

                debug!("usb: ufi: poll_command: Command: {}", kind);

                callback(Command {
                    class: self,
                    kind,
                    lun,
                })?;

                self.transport.poll()?;
            }
        }

        Ok(())
    }
}

impl<Bus, T> UsbClass<Bus> for Ufi<T>
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
            SUBCLASS_UFI,
            T::PROTO,
            None,
        )?;
        writer.interface(self.interface, CLASS_MASS_STORAGE, SUBCLASS_UFI, T::PROTO)?;

        self.transport.get_endpoint_descriptors(writer)?;

        Ok(())
    }

    fn reset(&mut self) {
        self.transport.reset()
    }

    fn control_in(&mut self, xfer: ControlIn<Bus>) {
        self.transport.control_in(xfer)
    }

    fn poll(&mut self) {
        if let Err(err) = self.transport.poll() {
            trace!("usb: ufi: poll: {}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPCODES: [u8; 19] = [
        FORMAT_UNIT,
        INQUIRY,
        MODE_SELECT,
        MODE_SENSE,
        PREVENT_ALLOW_MEDIUM_REMOVAL,
        READ_10,
        READ_12,
        READ_CAPACITY,
        READ_FORMAT_CAPACITIES,
        REQUEST_SENSE,
        REZERO_UNIT,
        SEEK_10,
        SEND_DIAGNOSTIC,
        START_STOP,
        TEST_UNIT_READY,
        VERIFY,
        WRITE_10,
        WRITE_12,
        WRITE_AND_VERIFY,
    ];

    /// The CDB length comes from the host's `bCBWCBLength` (1 to 16), not from the
    /// opcode: a command block too short for its opcode must not panic the device.
    #[test]
    fn parse_cb_short_command_blocks_do_not_panic() {
        for opcode in OPCODES {
            for len in 1..12 {
                let mut cb = [0u8; 12];
                cb[0] = opcode;
                let _ = parse_cb(&cb[..len]);
            }
        }
        assert!(matches!(parse_cb(&[]), UfiCommand::Unknown));
    }

    /// A full 12-byte command block whose fields are all different, so a field read
    /// from the wrong byte shows.
    fn cdb(opcode: u8) -> [u8; 12] {
        [
            opcode, 0x04, 0xC5, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0, 0,
        ]
    }

    #[test]
    fn parse_cb_full_command_blocks() {
        use UfiCommand as C;
        let p = |op| parse_cb(&cdb(op));
        assert!(matches!(
            p(REQUEST_SENSE),
            C::RequestSense { alloc_len: 0x34 }
        ));
        assert!(matches!(p(INQUIRY), C::Inquiry { alloc_len: 0x34 }));
        assert!(matches!(p(TEST_UNIT_READY), C::TestUnitReady));
        assert!(matches!(p(READ_CAPACITY), C::ReadCapacity));
        assert!(matches!(
            p(MODE_SENSE),
            C::ModeSense {
                page_control: 3,
                page_code: 0x05,
                param_list_len: 0x9ABC
            }
        ));
        assert!(matches!(
            p(READ_10),
            C::Read {
                lba: 0xC512_3456,
                len: 0x9ABC
            }
        ));
        assert!(matches!(
            p(READ_12),
            C::Read {
                lba: 0xC512_3456,
                len: 0x789A_BCDE
            }
        ));
        assert!(matches!(
            p(WRITE_10),
            C::Write {
                lba: 0xC512_3456,
                len: 0x9ABC,
                verify: false
            }
        ));
        assert!(matches!(
            p(WRITE_12),
            C::Write {
                lba: 0xC512_3456,
                len: 0x789A_BCDE,
                verify: false
            }
        ));
        assert!(matches!(
            p(WRITE_AND_VERIFY),
            C::Write {
                lba: 0xC512_3456,
                len: 0x9ABC,
                verify: true
            }
        ));
        assert!(matches!(
            p(FORMAT_UNIT),
            C::FormatUnit {
                track: 0xC5,
                parameter_list_len: 0x9ABC
            }
        ));
        assert!(matches!(
            p(MODE_SELECT),
            C::ModeSelect {
                parameter_list_len: 0x9ABC
            }
        ));
        assert!(matches!(
            p(READ_FORMAT_CAPACITIES),
            C::ReadFormatCapacities { alloc_len: 0x9ABC }
        ));
        assert!(matches!(p(REZERO_UNIT), C::RezeroUnit));
        assert!(matches!(p(SEEK_10), C::Seek { lba: 0xC512_3456 }));
        assert!(matches!(
            p(VERIFY),
            C::Verify {
                lba: 0xC512_3456,
                len: 0x9ABC
            }
        ));
        assert!(matches!(p(0xFF), C::Unknown));
    }

    #[test]
    fn parse_cb_flag_bits() {
        use UfiCommand as C;
        let with = |op: u8, at: usize, value: u8| {
            let mut cb = cdb(op);
            cb[at] = value;
            parse_cb(&cb)
        };
        // PREVENT ALLOW MEDIUM REMOVAL: byte 4, any non-zero value prevents
        assert!(matches!(
            with(PREVENT_ALLOW_MEDIUM_REMOVAL, 4, 0),
            C::PreventAllowMediumRemoval { prevent: false }
        ));
        assert!(matches!(
            with(PREVENT_ALLOW_MEDIUM_REMOVAL, 4, 1),
            C::PreventAllowMediumRemoval { prevent: true }
        ));
        // SEND DIAGNOSTIC: SelfTest, byte 1 bit 2
        assert!(matches!(
            with(SEND_DIAGNOSTIC, 1, 0b100),
            C::SendDiagnostic { default: true }
        ));
        assert!(matches!(
            with(SEND_DIAGNOSTIC, 1, 0b011),
            C::SendDiagnostic { default: false }
        ));
        // START STOP UNIT: Start is byte 4 bit 0, eject is LoEj without Start
        assert!(matches!(
            with(START_STOP, 4, 0b01),
            C::StartStop {
                start: true,
                eject: false
            }
        ));
        assert!(matches!(
            with(START_STOP, 4, 0b10),
            C::StartStop {
                start: false,
                eject: true
            }
        ));
        assert!(matches!(
            with(START_STOP, 4, 0b11),
            C::StartStop {
                start: true,
                eject: false
            }
        ));
        assert!(matches!(
            with(START_STOP, 4, 0b00),
            C::StartStop {
                start: false,
                eject: false
            }
        ));
    }
}
