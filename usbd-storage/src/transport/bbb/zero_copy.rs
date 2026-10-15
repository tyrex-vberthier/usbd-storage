//! Zero-copy data phases for [`BulkOnly`], behind the `transfer` feature.
//!
//! The subclass moves whole data phases through a [`TransferBus`] instead of staging them
//! packet by packet through the IO buffer. CBWs, CSWs and the padding of a short Data-In
//! still go through the ordinary packet path.
//!
//! The transport only does the accounting: it keeps the data phase from writing or reading
//! packets of its own while a transfer is queued, counts what each retired transfer moved
//! against `dCBWDataTransferLength`, and holds the CSW back until every transfer has been
//! retired. Retiring is the subclass' job, through [`BulkOnly::poll_data_transfer`]: that is
//! where its buffers come back.

use super::{BulkOnly, BulkOnlyError, BulkOnlyTransportResult, DataDirection, State};
use crate::fmt::trace;
use crate::transfer::{Retired, TransferBus};
use crate::transport::TransportError;
use core::borrow::BorrowMut;
use core::cmp::min;
use usb_device::bus::UsbBus;

/// A buffer the transport refused to submit, handed back with the reason.
#[derive(Debug)]
pub struct SubmitRejected {
    /// [`BulkOnlyError::InvalidState`] outside the matching data phase, or once the
    /// IO buffer holds staged data; [`BulkOnlyError::TransferLengthExceeded`] when the whole
    /// `dCBWDataTransferLength` has already been submitted; [`TransportError::Usb`] with
    /// what the bus answered, `WouldBlock` included.
    pub error: TransportError<BulkOnlyError>,
    /// The buffer that was passed to the submit call.
    pub buf: &'static mut [u8],
}

/// Zero-copy bookkeeping of one [`BulkOnly`].
#[derive(Default)]
pub(super) struct ZeroCopy {
    /// OUT data phases wait for the subclass instead of reading packets on their own.
    enabled: bool,
    /// A transfer has been submitted in the current data phase.
    in_use: bool,
    /// The subclass took the packet path for the current OUT data phase.
    per_packet_out: bool,
    /// Bytes submitted in the current data phase, retired or not.
    submitted: u32,
    /// Transfers submitted in the current data phase and not retired yet.
    in_flight: u32,
}

impl ZeroCopy {
    /// Forgets the current data phase; whether zero-copy is enabled stays.
    pub(super) fn end_data_phase(&mut self) {
        *self = Self {
            enabled: self.enabled,
            ..Self::default()
        };
    }
}

impl<Bus, Buf> BulkOnly<'_, Bus, Buf>
where
    Bus: UsbBus,
    Buf: BorrowMut<[u8]>,
{
    /// Makes OUT data phases wait for the subclass.
    ///
    /// By default the transport starts reading an OUT data phase into the IO buffer as soon
    /// as the CBW is in, which would take the first packets away from a transfer the
    /// subclass is about to submit. Once this is called, an OUT data phase reads nothing
    /// until the subclass either submits a transfer ([`submit_data_out`]) or calls
    /// [`read_data`], which opts that data phase into the packet path: the data then arrives
    /// on the following polls, and the command callback is called again until a status is
    /// set.
    ///
    /// [`submit_data_out`]: BulkOnly::submit_data_out
    /// [`read_data`]: BulkOnly::read_data
    pub fn enable_zero_copy(&mut self) {
        self.zero_copy.enabled = true;
    }

    /// Submits the first `len` bytes of `buf` as one Data-In transfer.
    ///
    /// `len` is clamped to what is left of `dCBWDataTransferLength` once the transfers
    /// already submitted in this data phase are counted. Several transfers can be queued
    /// at once; they reach the host in submission order. Once a transfer has been submitted
    /// in a data phase, [`write_data`] and [`try_write_data_all`] refuse to stage anything
    /// in it.
    ///
    /// # Errors
    /// Hands `buf` back in a [`SubmitRejected`].
    ///
    /// [`write_data`]: BulkOnly::write_data
    /// [`try_write_data_all`]: BulkOnly::try_write_data_all
    pub fn submit_data_in<B: TransferBus>(
        &mut self,
        bus: &B,
        buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), SubmitRejected> {
        let len = match self.submittable(State::DataTransferToHost, len, buf.len()) {
            Ok(len) => len,
            Err(error) => return Err(rejected(error, buf)),
        };
        bus.submit_write(self.in_ep.address(), buf, len)
            .map_err(|r| SubmitRejected {
                error: TransportError::Usb(r.error),
                buf: r.buf,
            })?;
        self.count_submitted(len);
        Ok(())
    }

    /// Submits a Data-Out transfer of at most `len` bytes into the start of `buf`.
    ///
    /// `len` is clamped as for [`submit_data_in`]. Once a transfer has been submitted in a
    /// data phase, [`read_data`] refuses to read anything in it.
    ///
    /// # Errors
    /// Hands `buf` back in a [`SubmitRejected`]. [`BulkOnlyError::InvalidState`] also when
    /// the subclass already took the packet path for this data phase with [`read_data`].
    ///
    /// [`submit_data_in`]: BulkOnly::submit_data_in
    /// [`read_data`]: BulkOnly::read_data
    pub fn submit_data_out<B: TransferBus>(
        &mut self,
        bus: &B,
        buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), SubmitRejected> {
        let len = match self.submittable(State::DataTransferFromHost, len, buf.len()) {
            Ok(len) => len,
            Err(error) => return Err(rejected(error, buf)),
        };
        bus.submit_read(self.out_ep.address(), buf, len)
            .map_err(|r| SubmitRejected {
                error: TransportError::Usb(r.error),
                buf: r.buf,
            })?;
        self.count_submitted(len);
        Ok(())
    }

    /// Retires the oldest finished transfer of the current data phase, if there is one.
    ///
    /// The bytes a retired transfer moved count as transferred. A transfer that ended in an
    /// error counts nothing; the error is in [`Retired::result`], with the buffer.
    ///
    /// Every submitted transfer has to be retired here: the transport sends the CSW only
    /// once none is left, even when the status was set before.
    ///
    /// Returns `Ok(None)` while the oldest transfer is still running, and when none is
    /// queued.
    ///
    /// # Errors
    /// None today; the `Result` leaves room for transport errors.
    pub fn poll_data_transfer<B: TransferBus>(
        &mut self,
        bus: &B,
    ) -> BulkOnlyTransportResult<Option<Retired>> {
        if self.zero_copy.in_flight == 0 {
            return Ok(None);
        }
        let ep = match self.cbw.direction {
            DataDirection::In => self.in_ep.address(),
            DataDirection::Out => self.out_ep.address(),
            DataDirection::NotExpected => return Ok(None),
        };
        let Some(retired) = bus.poll_transfer(ep) else {
            return Ok(None);
        };
        self.zero_copy.in_flight = self.zero_copy.in_flight.saturating_sub(1);
        if let Ok(n) = retired.result {
            self.mark_as_transferred(u32::try_from(n).unwrap_or(u32::MAX));
        }
        trace!(
            "usb: bbb: transfer retired, left: {}, in flight: {}",
            self.left_to_transfer, self.zero_copy.in_flight
        );
        Ok(Some(retired))
    }

    /// Whether the data phase handlers must leave the endpoints alone on this poll.
    ///
    /// Always while a transfer is queued: a packet of our own would land between, or
    /// inside, the subclass' transfers. Then, until a status is set, for as long as the
    /// subclass drives this data phase with transfers, and for an OUT data phase it has
    /// not decided about yet.
    pub(super) fn zero_copy_holds_data_phase(&self) -> bool {
        let zc = &self.zero_copy;
        if zc.in_flight > 0 {
            return true;
        }
        if self.left_to_transfer == 0 || self.has_status() {
            return false;
        }
        let undecided_out =
            matches!(self.state, State::DataTransferFromHost) && zc.enabled && !zc.per_packet_out;
        zc.in_use || undecided_out
    }

    /// Called by [`BulkOnly::read_data`]: the packet path is the subclass' choice for this
    /// OUT data phase, unless it already submitted a transfer in it.
    pub(super) fn take_per_packet_data_out(&mut self) -> BulkOnlyTransportResult<()> {
        if self.zero_copy.in_use {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }
        self.zero_copy.per_packet_out = true;
        Ok(())
    }

    /// Called by the staging writes: a data phase is either staged or zero-copy.
    pub(super) fn forbid_staging_in_zero_copy_phase(&self) -> BulkOnlyTransportResult<()> {
        if self.zero_copy.in_use {
            return Err(TransportError::Error(BulkOnlyError::InvalidState));
        }
        Ok(())
    }

    /// `len`, clamped to the buffer and to what is left of `dCBWDataTransferLength`, if a
    /// transfer may be submitted in `phase` now.
    ///
    /// A data phase is zero-copy from its first byte or not at all: once a byte went
    /// through the packet path, or sits in the IO buffer, what is left to submit is no
    /// longer `dCBWDataTransferLength` minus what was submitted.
    fn submittable(
        &self,
        phase: State,
        len: usize,
        buf_len: usize,
    ) -> Result<usize, BulkOnlyError> {
        let zc = &self.zero_copy;
        let packet_path_used = zc.per_packet_out
            || self.buf.available_read() > 0
            || (!zc.in_use && self.left_to_transfer != self.cbw.data_transfer_len);
        if core::mem::discriminant(&self.state) != core::mem::discriminant(&phase)
            || packet_path_used
        {
            return Err(BulkOnlyError::InvalidState);
        }
        let left = self.cbw.data_transfer_len.saturating_sub(zc.submitted);
        let len = min(
            min(len, buf_len),
            usize::try_from(left).unwrap_or(usize::MAX),
        );
        if len == 0 {
            return Err(BulkOnlyError::TransferLengthExceeded);
        }
        Ok(len)
    }

    fn count_submitted(&mut self, len: usize) {
        let zc = &mut self.zero_copy;
        zc.in_use = true;
        zc.in_flight = zc.in_flight.saturating_add(1);
        zc.submitted = zc
            .submitted
            .saturating_add(u32::try_from(len).unwrap_or(u32::MAX));
        trace!(
            "usb: bbb: transfer submitted: {}, in flight: {}",
            len, zc.in_flight
        );
    }
}

fn rejected(error: BulkOnlyError, buf: &'static mut [u8]) -> SubmitRejected {
    SubmitRejected {
        error: TransportError::Error(error),
        buf,
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        Host, MockBbb, PACKET_SIZES, Shared, cbw, enqueue, is_invalid_state, new_bbb,
    };
    use super::*;
    use crate::transfer::Rejected;
    use crate::transport::{CommandStatus, Transport};
    use core::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use usb_device::UsbError;
    use usb_device::endpoint::EndpointAddress;

    const IN_EP: u8 = 0x81;
    const OUT_EP: u8 = 0x01;

    struct Pending {
        ep: u8,
        buf: &'static mut [u8],
        len: usize,
        done: Option<Result<usize, UsbError>>,
    }

    /// A [`TransferBus`] whose transfers finish when the test says so.
    #[derive(Default)]
    struct MockTransfers {
        queue: RefCell<VecDeque<Pending>>,
        refuse: Cell<bool>,
    }

    impl MockTransfers {
        fn submit(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
        ) -> Result<(), Rejected> {
            if self.refuse.get() {
                return Err(Rejected {
                    error: UsbError::WouldBlock,
                    buf,
                });
            }
            self.queue.borrow_mut().push_back(Pending {
                ep: ep.into(),
                buf,
                len,
                done: None,
            });
            Ok(())
        }

        /// Finishes the oldest running transfer on `ep`. An OUT transfer receives `data`;
        /// an IN transfer returns the bytes it put on the wire.
        fn finish(&self, ep: u8, data: &[u8]) -> Vec<u8> {
            let mut queue = self.queue.borrow_mut();
            let p = queue
                .iter_mut()
                .find(|p| p.ep == ep && p.done.is_none())
                .expect("no running transfer on that endpoint");
            if ep == OUT_EP {
                let n = data.len().min(p.len);
                p.buf[..n].copy_from_slice(&data[..n]);
                p.done = Some(Ok(n));
                Vec::new()
            } else {
                p.done = Some(Ok(p.len));
                p.buf[..p.len].to_vec()
            }
        }

        fn lens(&self) -> Vec<usize> {
            self.queue.borrow().iter().map(|p| p.len).collect()
        }
    }

    impl TransferBus for MockTransfers {
        fn submit_write(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
        ) -> Result<(), Rejected> {
            self.submit(ep, buf, len)
        }

        fn submit_read(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
        ) -> Result<(), Rejected> {
            self.submit(ep, buf, len)
        }

        fn poll_transfer(&self, ep: EndpointAddress) -> Option<Retired> {
            let mut queue = self.queue.borrow_mut();
            let head = queue.iter().position(|p| p.ep == u8::from(ep))?;
            let result = queue[head].done?;
            let p = queue.remove(head)?;
            Some(Retired { buf: p.buf, result })
        }
    }

    fn dma(len: usize, fill: u8) -> &'static mut [u8] {
        Box::leak(vec![fill; len].into_boxed_slice())
    }

    /// A transport with the CBW read and the data phase started.
    fn started(ps: u16, len: u32, host: Host) -> (Shared, MockBbb) {
        let (shared, mut bbb) = new_bbb(ps);
        bbb.enable_zero_copy();
        enqueue(&shared, &cbw(len, host), ps);
        for _ in 0..64 {
            let _ = bbb.poll();
            if bbb.get_command().is_some() {
                break;
            }
        }
        assert!(bbb.get_command().is_some(), "ps={ps}: no command");
        (shared, bbb)
    }

    fn poll_n(bbb: &mut MockBbb, n: usize) {
        for _ in 0..n {
            let _ = bbb.poll();
        }
    }

    /// The bytes the device put on the packet path, and the CSW they end with as
    /// (status, residue). `None` when no CSW was sent.
    fn wire(shared: &Shared) -> (Vec<u8>, Option<(u8, u32)>) {
        let stream = std::mem::take(&mut *shared.input.lock().unwrap()).concat();
        if stream.len() < CSW_LEN
            || !stream[stream.len() - CSW_LEN..].starts_with(&CSW_SIGNATURE_LE)
        {
            return (stream, None);
        }
        let (data, csw) = stream.split_at(stream.len() - CSW_LEN);
        let residue = u32::from_le_bytes(csw[8..12].try_into().unwrap());
        (data.to_vec(), Some((csw[12], residue)))
    }

    use super::super::{CSW_LEN, CSW_SIGNATURE_LE, FILL_BYTE};
    use core::assert_matches;

    #[test]
    fn csw_waits_for_the_last_transfer_to_be_retired() {
        for ps in PACKET_SIZES {
            let (shared, mut bbb) = started(ps, 512, Host::DataIn);
            let bus = MockTransfers::default();

            bbb.submit_data_in(&bus, dma(512, 0xAB), 512).unwrap();
            bbb.set_status(CommandStatus::Passed, 512);
            poll_n(&mut bbb, 16);
            assert_eq!(wire(&shared), (vec![], None), "ps={ps}: sent while queued");

            assert_eq!(bus.finish(IN_EP, &[]), vec![0xAB; 512]);
            poll_n(&mut bbb, 16);
            assert_eq!(
                wire(&shared),
                (vec![], None),
                "ps={ps}: sent before retirement"
            );

            let retired = bbb.poll_data_transfer(&bus).unwrap().expect("retired");
            assert_eq!(retired.result, Ok(512), "ps={ps}");
            assert_eq!(
                retired.buf.len(),
                512,
                "ps={ps}: the whole buffer comes back"
            );
            poll_n(&mut bbb, 16);
            assert_eq!(wire(&shared), (vec![], Some((0, 0))), "ps={ps}");
            assert_matches!(bbb.state, State::CommandTransfer, "ps={ps}");
        }
    }

    #[test]
    fn queued_data_in_is_not_padded_twice() {
        // The status is set while both halves are still queued: the short-transfer
        // padding must not start until they are retired, or the host gets the phase twice.
        for ps in PACKET_SIZES {
            let (shared, mut bbb) = started(ps, 512, Host::DataIn);
            let bus = MockTransfers::default();

            bbb.submit_data_in(&bus, dma(256, 0x11), 256).unwrap();
            bbb.submit_data_in(&bus, dma(256, 0x22), 256).unwrap();
            bbb.set_status(CommandStatus::Passed, 512);
            poll_n(&mut bbb, 16);

            assert_eq!(
                bus.finish(IN_EP, &[]),
                vec![0x11; 256],
                "ps={ps}: FIFO order"
            );
            assert_eq!(
                bus.finish(IN_EP, &[]),
                vec![0x22; 256],
                "ps={ps}: FIFO order"
            );
            while bbb.poll_data_transfer(&bus).unwrap().is_some() {}
            poll_n(&mut bbb, 16);

            assert_eq!(wire(&shared), (vec![], Some((0, 0))), "ps={ps}");
        }
    }

    #[test]
    fn short_zero_copy_data_in_is_padded_after_retirement() {
        for ps in PACKET_SIZES {
            let (shared, mut bbb) = started(ps, 512, Host::DataIn);
            let bus = MockTransfers::default();

            bbb.submit_data_in(&bus, dma(100, 0x33), 100).unwrap();
            bus.finish(IN_EP, &[]);
            bbb.poll_data_transfer(&bus).unwrap().expect("retired");
            bbb.set_status(CommandStatus::Passed, 100);
            poll_n(&mut bbb, 128);

            assert_eq!(
                wire(&shared),
                (vec![FILL_BYTE; 412], Some((0, 412))),
                "ps={ps}"
            );
        }
    }

    #[test]
    fn submissions_are_clamped_to_the_transfer_length() {
        let (_shared, mut bbb) = started(64, 100, Host::DataIn);
        let bus = MockTransfers::default();

        bbb.submit_data_in(&bus, dma(64, 0), 64).unwrap();
        bbb.submit_data_in(&bus, dma(512, 0), 512).unwrap();
        assert_eq!(bus.lens(), vec![64, 36]);

        let rejected = bbb.submit_data_in(&bus, dma(8, 0), 8).unwrap_err();
        assert!(matches!(
            rejected.error,
            TransportError::Error(BulkOnlyError::TransferLengthExceeded)
        ));
        assert_eq!(rejected.buf.len(), 8, "the buffer comes back");
    }

    #[test]
    fn a_refused_submission_hands_the_buffer_back() {
        let (_shared, mut bbb) = started(64, 512, Host::DataIn);
        let bus = MockTransfers::default();
        bus.refuse.set(true);

        let buf = dma(512, 0);
        let ptr = buf.as_ptr();
        let rejected = bbb.submit_data_in(&bus, buf, 512).unwrap_err();
        assert!(matches!(
            rejected.error,
            TransportError::Usb(UsbError::WouldBlock)
        ));
        assert_eq!(rejected.buf.as_ptr(), ptr, "the same buffer comes back");
        assert_eq!(
            bbb.poll_data_transfer(&bus).unwrap().map(|r| r.result),
            None
        );

        // nothing was counted: the next attempt can still submit the whole phase
        bus.refuse.set(false);
        bbb.submit_data_in(&bus, rejected.buf, 512).unwrap();
        assert_eq!(bus.lens(), vec![512]);
    }

    #[test]
    fn an_enabled_out_phase_leaves_the_data_to_the_subclass() {
        for ps in PACKET_SIZES {
            let (shared, mut bbb) = started(ps, 64, Host::DataOut);
            let bus = MockTransfers::default();
            enqueue(&shared, &[0x5A; 64], ps);
            let packets = shared.out.lock().unwrap().len();

            poll_n(&mut bbb, 16);
            assert_eq!(
                shared.out.lock().unwrap().len(),
                packets,
                "ps={ps}: the transport read OUT data the subclass did not ask for"
            );

            bbb.submit_data_out(&bus, dma(64, 0), 64).unwrap();
            bus.finish(OUT_EP, &[0x5A; 64]);
            let retired = bbb.poll_data_transfer(&bus).unwrap().expect("retired");
            assert_eq!(retired.result, Ok(64), "ps={ps}");
            assert_eq!(retired.buf, &[0x5A; 64][..], "ps={ps}");

            bbb.set_status(CommandStatus::Passed, 64);
            poll_n(&mut bbb, 16);
            assert_eq!(wire(&shared), (vec![], Some((0, 0))), "ps={ps}");
        }
    }

    #[test]
    fn read_data_takes_an_enabled_out_phase_down_the_packet_path() {
        for ps in PACKET_SIZES {
            let (shared, mut bbb) = started(ps, 64, Host::DataOut);
            let bus = MockTransfers::default();
            enqueue(&shared, &[0x5A; 64], ps);

            let mut dst = [0u8; 64];
            assert_eq!(
                bbb.read_data(&mut dst).unwrap(),
                0,
                "ps={ps}: nothing read yet"
            );
            poll_n(&mut bbb, 16);
            assert_eq!(bbb.read_data(&mut dst).unwrap(), 64, "ps={ps}");
            assert_eq!(dst, [0x5A; 64], "ps={ps}");

            let rejected = bbb.submit_data_out(&bus, dma(64, 0), 64).unwrap_err();
            assert!(
                matches!(
                    rejected.error,
                    TransportError::Error(BulkOnlyError::InvalidState)
                ),
                "ps={ps}: a packet-path phase took a transfer"
            );
        }
    }

    #[test]
    fn a_phase_is_staged_or_zero_copy_never_both() {
        let bus = MockTransfers::default();

        let (_shared, mut bbb) = started(64, 512, Host::DataIn);
        bbb.submit_data_in(&bus, dma(64, 0), 64).unwrap();
        assert!(is_invalid_state(bbb.write_data(&[0; 8])));
        assert!(is_invalid_state(bbb.try_write_data_all(&[0; 8])));

        let (_shared, mut bbb) = started(64, 512, Host::DataIn);
        assert_eq!(bbb.write_data(&[0; 8]).unwrap(), 8);
        let rejected = bbb.submit_data_in(&bus, dma(64, 0), 64).unwrap_err();
        assert!(matches!(
            rejected.error,
            TransportError::Error(BulkOnlyError::InvalidState)
        ));

        // staged bytes already on the wire, none left in the IO buffer
        let (_shared, mut bbb) = started(64, 512, Host::DataIn);
        assert_eq!(bbb.write_data(&[0; 64]).unwrap(), 64);
        let _ = bbb.poll();
        assert_eq!(bbb.left_to_transfer, 448, "the staged packet went out");
        let rejected = bbb.submit_data_in(&bus, dma(64, 0), 64).unwrap_err();
        assert!(matches!(
            rejected.error,
            TransportError::Error(BulkOnlyError::InvalidState)
        ));

        let (_shared, mut bbb) = started(64, 64, Host::DataOut);
        bbb.submit_data_out(&bus, dma(64, 0), 64).unwrap();
        assert!(is_invalid_state(bbb.read_data(&mut [0; 8])));
    }

    #[test]
    fn zero_copy_stays_enabled_for_the_next_command() {
        let bus = MockTransfers::default();
        let (shared, mut bbb) = started(64, 64, Host::DataOut);
        bbb.submit_data_out(&bus, dma(64, 0), 64).unwrap();
        bus.finish(OUT_EP, &[0; 64]);
        bbb.poll_data_transfer(&bus).unwrap().expect("retired");
        bbb.set_status(CommandStatus::Passed, 64);
        poll_n(&mut bbb, 16);
        assert_matches!(bbb.state, State::CommandTransfer);

        enqueue(&shared, &cbw(64, Host::DataOut), 64);
        enqueue(&shared, &[0x5A; 64], 64);
        poll_n(&mut bbb, 16);
        assert_eq!(
            shared.out.lock().unwrap().len(),
            1,
            "the second command's OUT data was read without the subclass asking"
        );
    }

    #[test]
    fn submissions_need_the_matching_data_phase() {
        let bus = MockTransfers::default();

        let (_shared, mut bbb) = started(64, 64, Host::DataOut);
        let rejected = bbb.submit_data_in(&bus, dma(64, 0), 64).unwrap_err();
        assert!(matches!(
            rejected.error,
            TransportError::Error(BulkOnlyError::InvalidState)
        ));

        let (_shared, mut bbb) = started(64, 64, Host::DataIn);
        let rejected = bbb.submit_data_out(&bus, dma(64, 0), 64).unwrap_err();
        assert!(matches!(
            rejected.error,
            TransportError::Error(BulkOnlyError::InvalidState)
        ));
        assert!(bus.lens().is_empty());
    }

    #[test]
    fn a_reset_forgets_queued_transfers() {
        let (_shared, mut bbb) = started(64, 512, Host::DataIn);
        let bus = MockTransfers::default();
        bbb.submit_data_in(&bus, dma(512, 0), 512).unwrap();

        bbb.mass_storage_reset();
        bus.finish(IN_EP, &[]);
        assert_matches!(bbb.state, State::CommandTransfer);
        assert!(
            bbb.poll_data_transfer(&bus).unwrap().is_none(),
            "a transfer of the abandoned command was retired into the next one"
        );
        assert!(
            bus.poll_transfer(EndpointAddress::from(IN_EP)).is_some(),
            "the buffer stays with the bus"
        );
    }
}
