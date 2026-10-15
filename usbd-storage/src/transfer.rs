//! Zero-copy transfer queue abstraction for USB bulk endpoints.
//!
//! [`TransferBus`] abstracts a USB bus driver that can queue whole transfers per endpoint,
//! in FIFO order, straight out of (or into) the caller's memory, without staging them
//! through a packet buffer. It knows nothing about BOT or UAS and is implemented outside
//! this crate, for the specific controller.
//!
//! # Buffer ownership
//!
//! A DMA engine keeps reading or writing a buffer after the call that handed it over has
//! returned, so a borrowed slice cannot express the contract: nothing would stop the
//! caller from reusing or freeing the memory while the transfer is still running. The
//! buffer is therefore *moved* into the bus as a `&'static mut [u8]` and comes back to the
//! caller only once the transfer has finished, through [`TransferBus::poll_transfer`]
//! ([`Retired::buf`]) — or straight away, when the bus refuses it ([`Rejected::buf`]).
//! While the bus holds it, the caller cannot touch it.
//!
//! Only the first `len` bytes of the buffer take part in the transfer; the whole buffer is
//! handed back, so a caller can move a part of a larger buffer and get all of it back.
//!
//! # FIFO retirement order
//!
//! Transfers on one endpoint complete, and are retired, in the order they were submitted.
//! Each [`TransferBus::poll_transfer`] call retires at most one record.

use usb_device::{UsbError, endpoint::EndpointAddress};

/// A buffer the bus refused to queue, handed back together with the reason.
#[derive(Debug)]
pub struct Rejected {
    /// Why the transfer was not queued. [`UsbError::WouldBlock`] means the endpoint's
    /// queue is full: retire a completed transfer and submit again.
    pub error: UsbError,
    /// The buffer that was passed to the submit call.
    pub buf: &'static mut [u8],
}

/// A finished transfer: its buffer, and how it went.
#[derive(Debug)]
pub struct Retired {
    /// The buffer that was passed to the submit call, whole.
    pub buf: &'static mut [u8],
    /// The number of bytes transferred, or the error the transfer ended with.
    pub result: Result<usize, UsbError>,
}

/// A USB bus driver that supports zero-copy, whole-transfer queuing per endpoint.
///
/// See the [module documentation](self) for the buffer-ownership contract and the
/// retirement order.
pub trait TransferBus {
    /// Queues an IN transfer (device to host) of the first `len` bytes of `buf`.
    ///
    /// # Errors
    /// Hands `buf` back in a [`Rejected`] when the transfer is not queued:
    /// [`UsbError::WouldBlock`] when the endpoint's queue is full,
    /// [`UsbError::BufferOverflow`] when `len` exceeds `buf.len()`, or any error the
    /// driver reports for `ep`.
    fn submit_write(
        &self,
        ep: EndpointAddress,
        buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), Rejected>;

    /// Queues an OUT transfer (host to device) of at most `len` bytes into the start of
    /// `buf`.
    ///
    /// # Errors
    /// The same as [`submit_write`](TransferBus::submit_write).
    fn submit_read(
        &self,
        ep: EndpointAddress,
        buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), Rejected>;

    /// Retires the oldest finished transfer on `ep`, if there is one.
    ///
    /// Returns `None` while the oldest transfer is still running, or when nothing is
    /// queued.
    fn poll_transfer(&self, ep: EndpointAddress) -> Option<Retired>;
}
