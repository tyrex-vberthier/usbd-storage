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
    match cb[0] {
        TEST_UNIT_READY => ScsiCommand::TestUnitReady,
        INQUIRY => ScsiCommand::Inquiry {
            evpd: (cb[1] & 0b00000001) != 0,
            page_code: cb[2],
            alloc_len: u16::from_be_bytes([cb[3], cb[4]]),
        },
        REQUEST_SENSE => ScsiCommand::RequestSense {
            desc: (cb[1] & 0b00000001) != 0,
            alloc_len: cb[4],
        },
        READ_CAPACITY_10 => ScsiCommand::ReadCapacity10,
        READ_CAPACITY_16 => ScsiCommand::ReadCapacity16 {
            alloc_len: u32::from_be_bytes([cb[10], cb[11], cb[12], cb[13]]),
        },
        READ_10 => ScsiCommand::Read {
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
        READ_16 => ScsiCommand::Read {
            lba: u64::from_be_bytes((&cb[2..10]).try_into().unwrap()),
            len: u32::from_be_bytes((&cb[10..14]).try_into().unwrap()),
        },
        WRITE_10 => ScsiCommand::Write {
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
        WRITE_16 => ScsiCommand::Write {
            lba: u64::from_be_bytes((&cb[2..10]).try_into().unwrap()),
            len: u32::from_be_bytes((&cb[10..14]).try_into().unwrap()),
        },
        MODE_SENSE_6 => ScsiCommand::ModeSense6 {
            dbd: (cb[1] & 0b00001000) != 0,
            page_control: PageControl::try_from_primitive(cb[2] >> 6).unwrap(),
            page_code: cb[2] & 0b00111111,
            subpage_code: cb[3],
            alloc_len: cb[4],
        },
        MODE_SENSE_10 => ScsiCommand::ModeSense10 {
            dbd: (cb[1] & 0b00001000) != 0,
            page_control: PageControl::try_from_primitive(cb[2] >> 6).unwrap(),
            page_code: cb[2] & 0b00111111,
            subpage_code: cb[3],
            alloc_len: u16::from_be_bytes([cb[7], cb[8]]),
        },
        READ_FORMAT_CAPACITIES => ScsiCommand::ReadFormatCapacities {
            alloc_len: u16::from_be_bytes([cb[7], cb[8]]),
        },
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
    pub fn poll<F>(&mut self, mut callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>),
    {
        fn map_ignore<T>(res: Result<T, TransportError<BulkOnlyError>>) -> Result<(), UsbError> {
            match res {
                Ok(_)
                | Err(TransportError::Usb(UsbError::WouldBlock))
                | Err(TransportError::Error(_)) => Ok(()),
                Err(TransportError::Usb(err)) => Err(err),
            }
        }
        // drive transport in both directions before user action
        map_ignore(self.transport.read())?;
        map_ignore(self.transport.write())?;

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
                    match self.transport.write() {
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
                    map_ignore(self.transport.read())?;

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
        fn map_ignore<T>(res: Result<T, TransportError<BulkOnlyError>>) -> Result<(), UsbError> {
            match res {
                Ok(_)
                | Err(TransportError::Usb(UsbError::WouldBlock))
                | Err(TransportError::Error(_)) => Ok(()),
                Err(TransportError::Usb(err)) => Err(err),
            }
        }

        // During the OUT (host→device) data phase the bulk callback owns the
        // shared OUT endpoint via a single large dTD.  The per-packet
        // `transport.read()` path collides with that prime (it re-primes a
        // 512-byte per-packet OUT transfer on the same endpoint, blocking the
        // bulk prime and stealing the host's data), so skip it in that phase.
        // The IN data phase and the CBW/CSW phases use the normal path.
        if !self.transport.is_bulk_out_phase() {
            map_ignore(self.transport.read())?;
        }
        map_ignore(self.transport.write())?;

        if let Some(raw_cb) = self.transport.get_command() {
            if !self.transport.has_status() {
                let lun = raw_cb.lun;
                let kind = parse_cb(raw_cb.bytes);

                debug!("usb: scsi: Command (bulk): {}", kind);

                loop {
                    callback(
                        Command {
                            class: self,
                            kind,
                            lun,
                        },
                        bus,
                    );

                    match self.transport.write() {
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
                    // In the OUT data phase, advance to the CSW once the callback
                    // has set a status — but WITHOUT a per-packet read (which
                    // would collide with the bulk OUT prime).  Otherwise drive
                    // the normal per-packet read.
                    if self.transport.is_bulk_out_phase() {
                        map_ignore(self.transport.finish_bulk_out_phase())?;
                    } else {
                        map_ignore(self.transport.read())?;
                    }

                    break;
                }
            }
        }

        Ok(())
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
    pub fn poll_ring<F>(&mut self, bus: &Bus, mut callback: F) -> Result<(), UsbError>
    where
        F: FnMut(Command<ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>),
    {
        fn map_ignore<T>(res: Result<T, TransportError<BulkOnlyError>>) -> Result<(), UsbError> {
            match res {
                Ok(_)
                | Err(TransportError::Usb(UsbError::WouldBlock))
                | Err(TransportError::Error(_)) => Ok(()),
                Err(TransportError::Usb(err)) => Err(err),
            }
        }

        let in_addr = self.transport.in_ep_address();

        // drive transport in both directions before user action
        map_ignore(self.transport.read())?;
        map_ignore(self.transport.write_ring(bus.in_ep_drained(in_addr)))?;

        if let Some(raw_cb) = self.transport.get_command() {
            if !self.transport.has_status() {
                let lun = raw_cb.lun;
                let kind = parse_cb(raw_cb.bytes);

                debug!("usb: scsi: Command (ring): {}", kind);

                loop {
                    callback(Command {
                        class: self,
                        kind,
                        lun,
                    });

                    // Re-query drain state each pass: the callback may have primed
                    // more IN data, changing the ring occupancy.
                    match self.transport.write_ring(bus.in_ep_drained(in_addr)) {
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
                    map_ignore(self.transport.read())?;

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
}
