//! Zero-copy transfer queue abstraction for USB bulk endpoints.
//!
//! This module provides the [`TransferBus`] trait, which abstracts a USB bus
//! driver capable of queuing whole transfers per endpoint in FIFO order without
//! intermediate copies.
//!
//! # Buffer-validity contract
//!
//! Both [`TransferBus::submit_write`] and [`TransferBus::submit_read`] hand the
//! provided buffer slice directly to the DMA engine. **The caller must guarantee
//! that the buffer remains valid and is not accessed (read or written) from the
//! moment the submit call returns until [`TransferBus::poll_transfer`] retires
//! the corresponding record.**  Violating this contract is unsound: the DMA
//! controller may be reading or writing the memory concurrently.
//!
//! # FIFO retirement order
//!
//! Transfers are completed — and must be retired via [`TransferBus::poll_transfer`]
//! — in the same order they were submitted. Each `poll_transfer` call retires at
//! most one transfer record. The caller is responsible for draining completed
//! records promptly so that the driver's internal queue does not fill up.
//!
//! # `WouldBlock`
//!
//! Both submit methods return [`usb_device::UsbError::WouldBlock`] when the
//! driver's per-endpoint transfer budget is exhausted (the internal queue is
//! full). The caller should drain completed transfers via `poll_transfer` before
//! retrying.

use usb_device::{UsbError, endpoint::EndpointAddress};

/// A USB bus driver that supports zero-copy, whole-transfer queuing per endpoint.
///
/// Implementors queue IN and OUT transfers in FIFO order and signal completion
/// via [`poll_transfer`](TransferBus::poll_transfer).
///
/// ## FIFO retirement order
///
/// Transfers complete — and *must* be retired — in submission order.
/// Each [`poll_transfer`](TransferBus::poll_transfer) call retires at most one record.
///
/// ## Zero-copy validity contract
///
/// Buffers passed to [`submit_write`](TransferBus::submit_write) and
/// [`submit_read`](TransferBus::submit_read) are handed directly to the DMA
/// engine.  The buffer **must remain valid and unmodified** from the moment the
/// call returns until [`poll_transfer`](TransferBus::poll_transfer) retires the
/// corresponding record.
///
/// ## `WouldBlock`
///
/// Both submit methods return [`UsbError::WouldBlock`] when the driver's
/// per-endpoint budget is full.  Drain completed records with `poll_transfer`
/// before retrying.
pub trait TransferBus {
    /// Queue an IN transfer (device→host) from `buf`.
    ///
    /// The buffer is handed to the DMA engine zero-copy.  It must remain valid
    /// and unmodified until [`poll_transfer`](TransferBus::poll_transfer) retires
    /// this record.
    ///
    /// Returns [`UsbError::WouldBlock`] if the per-endpoint queue is full.
    fn submit_write(&self, ep: EndpointAddress, buf: &[u8]) -> Result<(), UsbError>;

    /// Queue an OUT transfer (host→device) into `buf`.
    ///
    /// The buffer is handed to the DMA engine zero-copy.  It must remain valid
    /// and unmodified until [`poll_transfer`](TransferBus::poll_transfer) retires
    /// this record.
    ///
    /// Returns [`UsbError::WouldBlock`] if the per-endpoint queue is full.
    fn submit_read(&self, ep: EndpointAddress, buf: &mut [u8]) -> Result<(), UsbError>;

    /// Retire the oldest completed transfer on `ep`.
    ///
    /// Returns:
    /// - `Some(Ok(n))` — the oldest transfer completed successfully with `n`
    ///   bytes transferred.
    /// - `Some(Err(_))` — the oldest transfer completed with a hardware error.
    /// - `None` — no transfer has completed yet.
    ///
    /// Transfers are retired in FIFO order (matching submission order).
    fn poll_transfer(&self, ep: EndpointAddress) -> Option<Result<usize, UsbError>>;
}
