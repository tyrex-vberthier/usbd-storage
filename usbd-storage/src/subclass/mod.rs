//! USB Mass Storage subclasses

#[cfg(all(feature = "bbb", feature = "scsi"))]
use crate::subclass::scsi::{Scsi, ScsiCommand};
#[cfg(all(feature = "bbb", feature = "ufi"))]
use crate::subclass::ufi::{Ufi, UfiCommand};
#[cfg(all(feature = "bbb", feature = "scsi", feature = "transfer"))]
use crate::transfer::TransferBus;
#[cfg(all(any(feature = "scsi", feature = "ufi"), feature = "bbb"))]
use {
    crate::transport::bbb::{BulkOnly, BulkOnlyError},
    crate::transport::{CommandStatus, TransportError},
    core::borrow::BorrowMut,
    usb_device::bus::UsbBus,
};

#[cfg(feature = "scsi")]
pub mod scsi;
#[cfg(feature = "ufi")]
pub mod ufi;

/// The subclass' command and a LUN it is addressed to
pub struct Command<'a, Kind, Class> {
    #[allow(dead_code)]
    class: &'a mut Class,
    pub kind: Kind,
    pub lun: u8,
}

/// [UFI] over [Bulk Only Transport] command
///
/// [UFI]: crate::subclass::ufi::Ufi
/// [Bulk Only Transport]: crate::transport::bbb::BulkOnly
#[cfg(all(feature = "bbb", feature = "ufi"))]
impl<'a, 'alloc, Bus: UsbBus + 'alloc, Buf: BorrowMut<[u8]>>
    Command<'a, UfiCommand, Ufi<BulkOnly<'alloc, Bus, Buf>>>
{
    /// [crate::transport::bbb::BulkOnly::read_data]
    pub fn read_data(&mut self, dst: &mut [u8]) -> Result<usize, TransportError<BulkOnlyError>> {
        self.class.transport.read_data(dst)
    }

    /// [crate::transport::bbb::BulkOnly::write_data]
    pub fn write_data(&mut self, src: &[u8]) -> Result<usize, TransportError<BulkOnlyError>> {
        self.class.transport.write_data(src)
    }

    /// [crate::transport::bbb::BulkOnly::try_write_data_all]
    pub fn try_write_data_all(&mut self, src: &[u8]) -> Result<(), TransportError<BulkOnlyError>> {
        self.class.transport.try_write_data_all(src)
    }

    pub fn pass(self) {
        self.class.transport.set_status(CommandStatus::Passed);
    }

    pub fn fail(self) {
        self.class.transport.set_status(CommandStatus::Failed);
    }

    pub fn fail_phase(self) {
        self.class.transport.set_status(CommandStatus::PhaseError);
    }
}

/// [SCSI] over [Bulk Only Transport] command
///
/// [SCSI]: crate::subclass::scsi::Scsi
/// [Bulk Only Transport]: crate::transport::bbb::BulkOnly
#[cfg(all(feature = "bbb", feature = "scsi"))]
impl<'a, 'alloc, Bus: UsbBus + 'alloc, Buf: BorrowMut<[u8]>>
    Command<'a, ScsiCommand, Scsi<BulkOnly<'alloc, Bus, Buf>>>
{
    /// [crate::transport::bbb::BulkOnly::read_data]
    pub fn read_data(&mut self, dst: &mut [u8]) -> Result<usize, TransportError<BulkOnlyError>> {
        self.class.transport.read_data(dst)
    }

    /// [crate::transport::bbb::BulkOnly::write_data]
    pub fn write_data(&mut self, src: &[u8]) -> Result<usize, TransportError<BulkOnlyError>> {
        self.class.transport.write_data(src)
    }

    /// [crate::transport::bbb::BulkOnly::try_write_data_all]
    pub fn try_write_data_all(&mut self, src: &[u8]) -> Result<(), TransportError<BulkOnlyError>> {
        self.class.transport.try_write_data_all(src)
    }

    pub fn pass(self) {
        self.class.transport.set_status(CommandStatus::Passed);
    }

    pub fn fail(self) {
        self.class.transport.set_status(CommandStatus::Failed);
    }

    pub fn fail_phase(self) {
        self.class.transport.set_status(CommandStatus::PhaseError);
    }

    /// [crate::transport::bbb::BulkOnly::read_data_transfer]
    #[cfg(feature = "transfer")]
    pub fn read_data_transfer<B: TransferBus>(
        &mut self,
        bus: &B,
        dst: &mut [u8],
    ) -> Result<usize, TransportError<BulkOnlyError>> {
        self.class.transport.read_data_transfer(bus, dst)
    }

    /// [crate::transport::bbb::BulkOnly::write_data_transfer]
    #[cfg(feature = "transfer")]
    pub fn write_data_transfer<B: TransferBus>(
        &mut self,
        bus: &B,
        src: &[u8],
    ) -> Result<usize, TransportError<BulkOnlyError>> {
        self.class.transport.write_data_transfer(bus, src)
    }

    /// [crate::transport::bbb::BulkOnly::write_data_transfer_pipelined]
    #[cfg(feature = "transfer")]
    pub fn write_data_transfer_pipelined<B: TransferBus>(
        &mut self,
        bus: &B,
        src: &[u8],
    ) -> Result<(), TransportError<BulkOnlyError>> {
        self.class.transport.write_data_transfer_pipelined(bus, src)
    }

    /// [crate::transport::bbb::BulkOnly::poll_data_transfer]
    #[cfg(feature = "transfer")]
    pub fn poll_data_transfer<B: TransferBus>(
        &mut self,
        bus: &B,
    ) -> Result<Option<usize>, TransportError<BulkOnlyError>> {
        self.class.transport.poll_data_transfer(bus)
    }
}
