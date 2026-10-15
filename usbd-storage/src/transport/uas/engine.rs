//! The UAS transport engine: the command and status pipes, and the data pipes it shares
//! with the Bulk-Only Transport.

use super::status::{STATUS_QUEUE_CAP, StatusMsg, StatusQueue, StatusQueueFull};
use super::{
    InsertError, IuParse, RC_INCORRECT_LUN, RC_OVERLAPPED_TAG, RC_TMF_NOT_SUPPORTED,
    STATUS_IU_HDR_LEN, TagTable, build_ready_iu, build_response_iu, build_status_iu, fixed_sense,
    parse_iu,
};
use crate::fmt::trace;
use crate::transfer::{Rejected, Retired, TransferBus};
use usb_device::UsbError;
use usb_device::bus::{UsbBus, UsbBusAllocator};
use usb_device::endpoint::{Endpoint, EndpointAddress, In, Out};

/// UAS transport engine.
///
/// `Uas` owns the two UAS-exclusive bulk endpoints (command OUT, status IN) and
/// stores the addresses of the shared data endpoints (bulk IN/OUT) that are also
/// used by [`BulkOnly`] in alt-0.
///
/// # Ordering invariant
///
/// RRDY/WRDY messages are enqueued in the same order their data phases are
/// submitted on the shared data pipes.  Because both the status queue and the
/// USB bulk pipe are FIFOs, the host observes ready-IU order == data-submit
/// order, satisfying the HS sequencing rule (§7 of the protocol reference).
///
/// [`BulkOnly`]: crate::transport::bbb::BulkOnly
pub struct Uas<'alloc, Bus: UsbBus> {
    /// Command pipe: bulk OUT, host → device.
    pub(crate) cmd_ep: Endpoint<'alloc, Bus, Out>,
    /// Status pipe: bulk IN, device → host.
    pub(crate) status_ep: Endpoint<'alloc, Bus, In>,
    /// Address of the shared data-IN endpoint (reuses BOT bulk IN).
    pub(crate) data_in: EndpointAddress,
    /// Address of the shared data-OUT endpoint (reuses BOT bulk OUT).
    pub(crate) data_out: EndpointAddress,
    /// In-flight command tag table.
    pub table: TagTable,
    /// Pending status-pipe messages.
    status_q: StatusQueue,
}

impl<'alloc, Bus: UsbBus> Uas<'alloc, Bus> {
    /// Allocate the UAS-exclusive endpoints and create the engine.
    ///
    /// `data_in` and `data_out` are the endpoint addresses of the BOT bulk
    /// endpoints that are shared with the alt-0 setting; they are stored here
    /// so `pump` can drive data-phase transfers on them.
    pub(crate) fn new(
        alloc: &'alloc UsbBusAllocator<Bus>,
        packet_size: u16,
        data_in: EndpointAddress,
        data_out: EndpointAddress,
    ) -> Self {
        Self {
            // Command pipe: host sends Command IUs / Task Mgmt IUs here.
            cmd_ep: alloc.bulk(packet_size),
            // Status pipe: device sends RRDY/WRDY/Status/Response IUs here.
            status_ep: alloc.bulk(packet_size),
            data_in,
            data_out,
            table: TagTable::new(),
            status_q: StatusQueue::new(),
        }
    }

    /// Drive the UAS engine one step.
    ///
    /// * Reads one command-pipe packet and dispatches it:
    ///   - Command IU, LUN 0 → insert into the tag table; on collision push
    ///     `Response { RC_OVERLAPPED_TAG }`; on full push `TaskSetFull`.
    ///   - Command IU, LUN ≠ 0 → push `Response { RC_INCORRECT_LUN }`.
    ///   - Task Management IU → push `Response { RC_TMF_NOT_SUPPORTED }`.
    ///   - Parse error → logged at TRACE level, packet dropped.
    /// * Drains pending status-queue entries onto the status pipe until the
    ///   queue is empty or the endpoint reports `WouldBlock`.
    pub fn pump(&mut self) {
        self.pump_cmd_pipe();
        self.drain_status();
    }

    /// Drain queued status-pipe messages onto the status endpoint.
    ///
    /// Sends from the FIFO head until the queue is empty or the endpoint
    /// reports `WouldBlock` (the entry is kept and retried on the next
    /// drain).
    ///
    /// Callers MUST invoke this after every batch of [`Self::enqueue_status`]
    /// calls made outside `pump` (e.g. at the end of an ISR service pass).
    /// The host only NAK-polls the status pipe while waiting for a
    /// ready/status IU, and NAKed polls raise no interrupt — a message left
    /// in the queue "until the next pump" therefore deadlocks the link
    /// (observed on hardware 2026-06-11: INQUIRY accepted and staged, RRDY
    /// enqueued but never written, no further interrupt arrived, host reset
    /// the device after 20 s).
    pub fn drain_status(&mut self) {
        // Bounded by what the queue can hold, so a queue that misbehaves cannot hang
        // the caller.
        for _ in 0..STATUS_QUEUE_CAP {
            let Some(msg) = self.status_q.peek().copied() else {
                break;
            };
            if !self.try_send_msg(msg) {
                break;
            }
            self.status_q.pop();
        }
    }

    /// Read one packet from the command pipe and dispatch it.
    fn pump_cmd_pipe(&mut self) {
        let mut buf = [0u8; 32];
        match self.cmd_ep.read(&mut buf) {
            Ok(n) => {
                let raw = buf.get(..n).unwrap_or(&buf[..0]);
                self.dispatch_cmd(raw);
            }
            Err(UsbError::WouldBlock) => { /* nothing ready yet */ }
            Err(_e) => {
                trace!("uas: cmd pipe read error");
            }
        }
    }

    /// Dispatch a raw command-pipe packet.
    fn dispatch_cmd(&mut self, raw: &[u8]) {
        match parse_iu(raw) {
            Ok(IuParse::Command(iu)) => {
                if iu.lun != 0 {
                    trace!("uas: incorrect LUN {}", iu.lun);
                    let _ = self.status_q.push(StatusMsg::Response {
                        tag: iu.tag,
                        code: RC_INCORRECT_LUN,
                    });
                    return;
                }
                let kind = iu.parse_kind();
                match self.table.insert(iu.tag, iu.lun, kind) {
                    Ok(()) => {
                        trace!("uas: inserted tag {}", iu.tag);
                    }
                    Err(InsertError::Overlapped) => {
                        trace!("uas: overlapped tag {}", iu.tag);
                        let _ = self.status_q.push(StatusMsg::Response {
                            tag: iu.tag,
                            code: RC_OVERLAPPED_TAG,
                        });
                    }
                    Err(InsertError::Full) => {
                        trace!("uas: tag table full, tag {}", iu.tag);
                        let _ = self.status_q.push(StatusMsg::TaskSetFull { tag: iu.tag });
                    }
                }
            }
            Ok(IuParse::TaskMgmt(tm)) => {
                trace!("uas: task mgmt IU, function {}", tm.function);
                let _ = self.status_q.push(StatusMsg::Response {
                    tag: tm.tag,
                    code: RC_TMF_NOT_SUPPORTED,
                });
            }
            Err(_e) => {
                trace!("uas: cmd pipe parse error");
            }
        }
    }

    /// Encode `msg` and write it on the status pipe via the **packet
    /// (staging) path** — `Endpoint::write`, NOT the zero-copy
    /// `TransferBus::submit_write`.
    ///
    /// The packet path copies the IU into the driver's staging buffer, so
    /// the stack-local IU bytes need not outlive this call, and the driver
    /// auto-reaps retired fire-and-forget staging records on the next write.
    /// The zero-copy path is wrong here on both counts: its records must be
    /// retired via `poll_transfer` (which no one calls for the status pipe —
    /// HW-observed 2026-06-11: `tds_in_use` climbed 6→7→8 then permanent
    /// `WouldBlock`, muting the status pipe after ~8 IUs), and it DMAs the
    /// caller's buffer after the stack frame is gone.
    ///
    /// Returns `true` if the write was accepted; `false` on `WouldBlock`
    /// (caller keeps the message and retries next drain).
    fn try_send_msg(&self, msg: StatusMsg) -> bool {
        /// SAM SCSI status: GOOD.
        const SAM_STAT_GOOD: u8 = 0x00;
        /// SAM SCSI status: CHECK CONDITION.
        const SAM_STAT_CHECK_CONDITION: u8 = 0x02;
        /// SAM SCSI status: TASK SET FULL.
        const SAM_STAT_TASK_SET_FULL: u8 = 0x28;

        match msg {
            StatusMsg::ReadReady { tag } => {
                let iu = build_ready_iu(true, tag);
                self.status_ep.write(&iu).is_ok()
            }
            StatusMsg::WriteReady { tag } => {
                let iu = build_ready_iu(false, tag);
                self.status_ep.write(&iu).is_ok()
            }
            StatusMsg::Good { tag } => {
                let (iu, used) = build_status_iu(tag, SAM_STAT_GOOD, &[]);
                let bytes = iu.get(..used).unwrap_or(&iu[..STATUS_IU_HDR_LEN]);
                self.status_ep.write(bytes).is_ok()
            }
            StatusMsg::Check {
                tag,
                key,
                asc,
                ascq,
            } => {
                let sense = fixed_sense(key, asc, ascq);
                let (iu, used) = build_status_iu(tag, SAM_STAT_CHECK_CONDITION, &sense);
                let bytes = iu.get(..used).unwrap_or(&iu[..STATUS_IU_HDR_LEN]);
                self.status_ep.write(bytes).is_ok()
            }
            StatusMsg::TaskSetFull { tag } => {
                let (iu, used) = build_status_iu(tag, SAM_STAT_TASK_SET_FULL, &[]);
                let bytes = iu.get(..used).unwrap_or(&iu[..STATUS_IU_HDR_LEN]);
                self.status_ep.write(bytes).is_ok()
            }
            StatusMsg::Response { tag, code } => {
                let iu = build_response_iu(tag, code);
                self.status_ep.write(&iu).is_ok()
            }
        }
    }

    /// Enqueue a [`StatusMsg`] for later transmission on the status pipe.
    ///
    /// # Errors
    ///
    /// Returns [`StatusQueueFull`] only on a logic bug; the queue capacity
    /// covers every possible in-flight tag plus a margin.
    pub fn enqueue_status(&mut self, msg: StatusMsg) -> Result<(), StatusQueueFull> {
        self.status_q.push(msg)
    }

    /// Return `true` if no status messages are pending.
    pub fn status_drained(&self) -> bool {
        self.status_q.is_empty()
    }

    /// Queues a data-IN transfer (device to host) of the first `len` bytes of `buf` on the
    /// shared bulk-IN endpoint.
    ///
    /// # Errors
    /// Hands `buf` back when the bus refuses it, see [`TransferBus::submit_write`].
    pub fn submit_data_in<B: TransferBus>(
        &self,
        bus: &B,
        buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), Rejected> {
        bus.submit_write(self.data_in, buf, len)
    }

    /// Retires the oldest finished data-IN transfer, handing its buffer back.
    ///
    /// Returns `None` while it is still running, or when none is queued.
    pub fn poll_data_in<B: TransferBus>(&self, bus: &B) -> Option<Retired> {
        bus.poll_transfer(self.data_in)
    }

    /// Queues a data-OUT transfer (host to device) of at most `len` bytes into the start of
    /// `buf`, on the shared bulk-OUT endpoint.
    ///
    /// # Errors
    /// Hands `buf` back when the bus refuses it, see [`TransferBus::submit_read`].
    pub fn submit_data_out<B: TransferBus>(
        &self,
        bus: &B,
        buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), Rejected> {
        bus.submit_read(self.data_out, buf, len)
    }

    /// Retires the oldest finished data-OUT transfer, handing its buffer back.
    ///
    /// Returns `None` while it is still running, or when none is queued.
    pub fn poll_data_out<B: TransferBus>(&self, bus: &B) -> Option<Retired> {
        bus.poll_transfer(self.data_out)
    }

    /// Reset the engine: clear the tag table, flush the status queue.
    ///
    /// Called on USB reset or SET_INTERFACE to a new alternate setting.
    pub fn reset(&mut self) {
        self.table.clear();
        self.status_q.clear();
    }

    /// Write the alt-1 UAS endpoint descriptors to `writer` in f_tcm HS order.
    ///
    /// The data endpoints (`data_in_ep`, `data_out_ep`) are the shared BOT
    /// endpoints passed in from the caller; the status and command endpoints
    /// are owned by `self`.
    ///
    /// Order (§6.3 of the protocol reference):
    /// data-in + PU3, data-out + PU4, status + PU2, cmd + PU1.
    ///
    /// Each endpoint descriptor is immediately followed by its 4-byte Pipe
    /// Usage descriptor (`[0x04, 0x24, bPipeID, 0x00]`).
    pub(crate) fn write_alt1_descriptors(
        &self,
        writer: &mut usb_device::descriptor::DescriptorWriter,
        data_in_ep: &Endpoint<'alloc, Bus, In>,
        data_out_ep: &Endpoint<'alloc, Bus, Out>,
    ) -> usb_device::Result<()> {
        // data-in (shared BOT bulk IN): Pipe ID 3
        writer.endpoint(data_in_ep)?;
        writer.write(0x24, &[0x03, 0x00])?;

        // data-out (shared BOT bulk OUT): Pipe ID 4
        writer.endpoint(data_out_ep)?;
        writer.write(0x24, &[0x04, 0x00])?;

        // status (UAS-exclusive bulk IN): Pipe ID 2
        writer.endpoint(&self.status_ep)?;
        writer.write(0x24, &[0x02, 0x00])?;

        // command (UAS-exclusive bulk OUT): Pipe ID 1
        writer.endpoint(&self.cmd_ep)?;
        writer.write(0x24, &[0x01, 0x00])?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::UAS_QDEPTH;
    use super::*;
    use crate::subclass::scsi::ScsiCommand;
    use std::collections::{HashMap, VecDeque};
    use std::result;
    use std::sync::{Arc, Mutex};
    use usb_device::UsbDirection;
    use usb_device::bus::PollResult;
    use usb_device::class_prelude::EndpointType;
    use usb_device::device::{UsbDeviceBuilder, UsbVidPid};

    type TestResult = result::Result<(), Box<dyn std::error::Error>>;

    const DATA_IN: u8 = 0x81;
    const DATA_OUT: u8 = 0x01;

    #[derive(Default)]
    struct Wire {
        /// host -> device packets, by endpoint address
        out: HashMap<u8, VecDeque<Vec<u8>>>,
        /// device -> host packets, by endpoint address
        sent: HashMap<u8, Vec<Vec<u8>>>,
        /// the status pipe answers `WouldBlock` while set
        busy: bool,
        next_index: u8,
    }

    #[derive(Clone, Default)]
    struct MockBus(Arc<Mutex<Wire>>);

    impl UsbBus for MockBus {
        fn alloc_ep(
            &mut self,
            ep_dir: UsbDirection,
            _ep_addr: Option<EndpointAddress>,
            _ep_type: EndpointType,
            _max_packet_size: u16,
            _interval: u8,
        ) -> usb_device::Result<EndpointAddress> {
            let mut wire = self.0.lock().unwrap();
            wire.next_index += 1;
            Ok(EndpointAddress::from_parts(
                usize::from(wire.next_index) + 1,
                ep_dir,
            ))
        }
        fn enable(&mut self) {}
        fn reset(&self) {}
        fn set_device_address(&self, _addr: u8) {}
        fn write(&self, ep: EndpointAddress, buf: &[u8]) -> usb_device::Result<usize> {
            let mut wire = self.0.lock().unwrap();
            if wire.busy {
                return Err(UsbError::WouldBlock);
            }
            wire.sent.entry(ep.into()).or_default().push(buf.to_vec());
            Ok(buf.len())
        }
        fn read(&self, ep: EndpointAddress, buf: &mut [u8]) -> usb_device::Result<usize> {
            let mut wire = self.0.lock().unwrap();
            match wire
                .out
                .get_mut(&u8::from(ep))
                .and_then(VecDeque::pop_front)
            {
                Some(pkt) => {
                    buf[..pkt.len()].copy_from_slice(&pkt);
                    Ok(pkt.len())
                }
                None => Err(UsbError::WouldBlock),
            }
        }
        fn set_stalled(&self, _ep: EndpointAddress, _stalled: bool) {}
        fn is_stalled(&self, _ep: EndpointAddress) -> bool {
            false
        }
        fn suspend(&self) {}
        fn resume(&self) {}
        fn poll(&self) -> PollResult {
            PollResult::None
        }
    }

    fn new_uas() -> (MockBus, Uas<'static, MockBus>) {
        let bus = MockBus::default();
        let alloc = Box::leak(Box::new(UsbBusAllocator::new(bus.clone())));
        let uas = Uas::new(
            alloc,
            64,
            EndpointAddress::from(DATA_IN),
            EndpointAddress::from(DATA_OUT),
        );
        // Endpoint IO reaches the bus only once the allocator is frozen.
        core::mem::forget(UsbDeviceBuilder::new(alloc, UsbVidPid(0xabcd, 0xabcd)).build());
        (bus, uas)
    }

    /// A Command IU: INQUIRY for `tag` on `lun`.
    fn command_iu(tag: u16, lun: u8) -> Vec<u8> {
        let mut iu = vec![0u8; 32];
        iu[0] = 0x01;
        iu[2..4].copy_from_slice(&tag.to_be_bytes());
        iu[9] = lun;
        iu[16..22].copy_from_slice(&[0x12, 0, 0, 0, 36, 0]);
        iu
    }

    fn host_sends(bus: &MockBus, uas: &Uas<'static, MockBus>, iu: Vec<u8>) {
        let ep = uas.cmd_ep.address().into();
        bus.0
            .lock()
            .unwrap()
            .out
            .entry(ep)
            .or_default()
            .push_back(iu);
    }

    fn status_pipe(bus: &MockBus, uas: &Uas<'static, MockBus>) -> Vec<Vec<u8>> {
        let ep = uas.status_ep.address().into();
        bus.0.lock().unwrap().sent.remove(&ep).unwrap_or_default()
    }

    #[test]
    fn a_command_on_lun_0_is_queued_by_tag() -> TestResult {
        let (bus, mut uas) = new_uas();
        host_sends(&bus, &uas, command_iu(7, 0));

        uas.pump();

        assert_eq!(uas.table.len(), 1, "one command queued");
        let head = uas.table.head().ok_or("no head")?;
        assert_eq!(head.tag, 7, "queued under its tag");
        assert!(
            matches!(head.kind, ScsiCommand::Inquiry { .. }),
            "parsed CDB"
        );
        assert!(status_pipe(&bus, &uas).is_empty(), "nothing to say yet");
        Ok(())
    }

    #[test]
    fn protocol_errors_are_answered_on_the_status_pipe() -> TestResult {
        let (bus, mut uas) = new_uas();

        host_sends(&bus, &uas, command_iu(1, 3));
        uas.pump();
        assert_eq!(
            status_pipe(&bus, &uas),
            vec![build_response_iu(1, RC_INCORRECT_LUN).to_vec()],
            "wrong LUN"
        );

        host_sends(&bus, &uas, command_iu(2, 0));
        uas.pump();
        host_sends(&bus, &uas, command_iu(2, 0));
        uas.pump();
        assert_eq!(
            status_pipe(&bus, &uas),
            vec![build_response_iu(2, RC_OVERLAPPED_TAG).to_vec()],
            "overlapped tag"
        );

        let mut tm = vec![0u8; 16];
        tm[0] = 0x05;
        tm[3] = 9;
        host_sends(&bus, &uas, tm);
        uas.pump();
        assert_eq!(
            status_pipe(&bus, &uas),
            vec![build_response_iu(9, RC_TMF_NOT_SUPPORTED).to_vec()],
            "task management"
        );

        host_sends(&bus, &uas, vec![0x42; 8]);
        uas.pump();
        assert!(
            status_pipe(&bus, &uas).is_empty(),
            "garbage is dropped silently"
        );
        Ok(())
    }

    #[test]
    fn a_full_table_answers_task_set_full() -> TestResult {
        let (bus, mut uas) = new_uas();
        for tag in 1..=u16::try_from(UAS_QDEPTH)? {
            host_sends(&bus, &uas, command_iu(tag, 0));
            uas.pump();
        }
        assert!(
            status_pipe(&bus, &uas).is_empty(),
            "a full queue depth is accepted"
        );

        host_sends(&bus, &uas, command_iu(99, 0));
        uas.pump();
        let (iu, used) = build_status_iu(99, 0x28, &[]);
        assert_eq!(
            status_pipe(&bus, &uas),
            vec![iu[..used].to_vec()],
            "TASK SET FULL"
        );
        Ok(())
    }

    #[test]
    fn every_status_message_goes_out_as_its_iu() -> TestResult {
        let (bus, mut uas) = new_uas();
        let msgs = [
            StatusMsg::ReadReady { tag: 1 },
            StatusMsg::WriteReady { tag: 2 },
            StatusMsg::Good { tag: 3 },
            StatusMsg::Check {
                tag: 4,
                key: 0x05,
                asc: 0x24,
                ascq: 0x00,
            },
            StatusMsg::TaskSetFull { tag: 5 },
            StatusMsg::Response {
                tag: 6,
                code: RC_INCORRECT_LUN,
            },
        ];
        for msg in msgs {
            uas.enqueue_status(msg).map_err(|_| "queue full")?;
        }
        uas.drain_status();

        let good = build_status_iu(3, 0x00, &[]);
        let check = build_status_iu(4, 0x02, &fixed_sense(0x05, 0x24, 0x00));
        let full = build_status_iu(5, 0x28, &[]);
        assert_eq!(
            status_pipe(&bus, &uas),
            vec![
                build_ready_iu(true, 1).to_vec(),
                build_ready_iu(false, 2).to_vec(),
                good.0[..good.1].to_vec(),
                check.0[..check.1].to_vec(),
                full.0[..full.1].to_vec(),
                build_response_iu(6, RC_INCORRECT_LUN).to_vec(),
            ]
        );
        assert!(uas.status_drained(), "all sent");
        Ok(())
    }

    #[test]
    fn a_busy_status_pipe_keeps_the_message_for_the_next_drain() -> TestResult {
        let (bus, mut uas) = new_uas();
        bus.0.lock().unwrap().busy = true;
        uas.enqueue_status(StatusMsg::Good { tag: 1 })
            .map_err(|_| "queue full")?;
        uas.enqueue_status(StatusMsg::Good { tag: 2 })
            .map_err(|_| "queue full")?;

        uas.drain_status();
        assert!(status_pipe(&bus, &uas).is_empty(), "nothing went out");
        assert!(!uas.status_drained(), "both kept");

        bus.0.lock().unwrap().busy = false;
        uas.drain_status();
        let first = build_status_iu(1, 0x00, &[]);
        let second = build_status_iu(2, 0x00, &[]);
        assert_eq!(
            status_pipe(&bus, &uas),
            vec![first.0[..first.1].to_vec(), second.0[..second.1].to_vec()],
            "sent in order once the pipe frees up"
        );
        Ok(())
    }

    #[test]
    fn reset_forgets_commands_and_pending_status() -> TestResult {
        let (bus, mut uas) = new_uas();
        host_sends(&bus, &uas, command_iu(1, 0));
        uas.pump();
        bus.0.lock().unwrap().busy = true;
        uas.enqueue_status(StatusMsg::Good { tag: 1 })
            .map_err(|_| "queue full")?;
        uas.drain_status();

        uas.reset();

        assert!(uas.table.is_empty(), "no command left");
        assert!(uas.status_drained(), "no status left");
        Ok(())
    }

    /// A [`TransferBus`] that finishes every transfer at once and records where it went.
    #[derive(Default)]
    struct InstantTransfers(Mutex<VecDeque<(u8, Retired)>>);

    impl InstantTransfers {
        fn queue(&self, ep: EndpointAddress, buf: &'static mut [u8], len: usize) {
            let retired = Retired {
                buf,
                result: Ok(len),
            };
            self.0.lock().unwrap().push_back((ep.into(), retired));
        }
    }

    impl TransferBus for InstantTransfers {
        fn submit_write(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
        ) -> Result<(), Rejected> {
            self.queue(ep, buf, len);
            Ok(())
        }
        fn submit_read(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
        ) -> Result<(), Rejected> {
            self.queue(ep, buf, len);
            Ok(())
        }
        fn poll_transfer(&self, ep: EndpointAddress) -> Option<Retired> {
            let mut queue = self.0.lock().unwrap();
            let at = queue.iter().position(|(e, _)| *e == u8::from(ep))?;
            queue.remove(at).map(|(_, retired)| retired)
        }
    }

    #[test]
    fn data_phases_run_on_the_shared_data_pipes() -> TestResult {
        let (_bus, uas) = new_uas();
        let transfers = InstantTransfers::default();

        uas.submit_data_in(&transfers, Box::leak(Box::new([0xAA; 64])), 64)
            .map_err(|_| "refused")?;
        uas.submit_data_out(&transfers, Box::leak(Box::new([0u8; 32])), 32)
            .map_err(|_| "refused")?;

        let din = uas.poll_data_in(&transfers).ok_or("nothing on data-in")?;
        assert_eq!(
            din.result,
            Ok(64),
            "the IN transfer, on the bulk-IN endpoint"
        );
        assert_eq!(din.buf.len(), 64, "its buffer comes back");
        let dout = uas.poll_data_out(&transfers).ok_or("nothing on data-out")?;
        assert_eq!(
            dout.result,
            Ok(32),
            "the OUT transfer, on the bulk-OUT endpoint"
        );
        assert!(uas.poll_data_in(&transfers).is_none(), "nothing left");
        Ok(())
    }
}
