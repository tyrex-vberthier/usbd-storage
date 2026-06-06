//! Trait for buses that can prime a single large bulk transfer (multi-packet dTD).
//!
//! The [`BulkBus`] trait abstracts over USB bus implementations that expose a
//! "prime and poll" API for large bulk transfers — i.e., the caller hands an
//! entire buffer to the hardware in one shot, then polls for completion rather
//! than chopping the data into individual `max_packet_size` writes.
//!
//! The `imxrt-bulk` feature gates the blanket `impl BulkBus for
//! imxrt_usbd::BusAdapter` that forwards to the inherent methods on that
//! driver.  All other code (the generic `BulkOnly` helpers, the test
//! infrastructure) depends only on the trait itself and compiles without the
//! feature.

use usb_device::endpoint::EndpointAddress;
use usb_device::UsbError;

/// A USB bus that can prime a single large bulk transfer.
///
/// Implementations should map to a hardware "dTD chain" or equivalent: the
/// entire `buf` slice is handed to the controller in one operation, and the
/// caller polls [`bulk_poll`] until it reports completion.
pub trait BulkBus {
    /// Prime a Bulk IN (device→host) transfer with the contents of `buf`.
    ///
    /// Returns the number of bytes accepted by the controller on success.
    /// Returns [`UsbError::WouldBlock`] if a prior transfer is still in flight.
    fn bulk_write(&self, ep: EndpointAddress, buf: &[u8]) -> Result<usize, UsbError>;

    /// Prime a Bulk OUT (host→device) transfer into `buf`.
    ///
    /// The controller will fill `buf` when the host sends data.  Call
    /// [`bulk_poll`] to detect completion.
    /// Returns [`UsbError::WouldBlock`] if a prior transfer is still in flight.
    fn bulk_read_prime(&self, ep: EndpointAddress, buf: &mut [u8]) -> Result<(), UsbError>;

    /// Poll whether the transfer on `ep` has completed.
    ///
    /// Returns `Some(n)` with the byte count once complete, or `None` while
    /// still in progress.
    fn bulk_poll(&self, ep: EndpointAddress) -> Option<usize>;
}

/// `imxrt-usbd`-specific implementation.
///
/// Enabled only when the `imxrt-bulk` feature is active.  The consuming
/// firmware redirects the git dependency to a local path via `[patch]` in its
/// own `Cargo.toml`, so this will not be pulled from crates.io.
#[cfg(feature = "imxrt-bulk")]
impl BulkBus for imxrt_usbd::BusAdapter {
    fn bulk_write(&self, ep: EndpointAddress, buf: &[u8]) -> Result<usize, UsbError> {
        // Forward to the DISTINCTLY-named inherent method to avoid infinite
        // recursion (a plain `self.bulk_write(...)` would re-enter this impl).
        self.bulk_prime_write(ep, buf)
    }

    fn bulk_read_prime(&self, ep: EndpointAddress, buf: &mut [u8]) -> Result<(), UsbError> {
        self.bulk_prime_read(ep, buf)
    }

    fn bulk_poll(&self, ep: EndpointAddress) -> Option<usize> {
        self.bulk_poll_complete(ep)
    }
}
