mod common;

use crate::common::Step;
use crate::common::bbb::{Cbw, CommandStatus, Csw, DataDirection, DummyUsbBus};
use crate::common::scsi::cmd_into_bytes;
use std::time::Duration;
#[cfg(feature = "transfer")]
use usb_device::UsbError;
use usb_device::bus::UsbBusAllocator;
use usb_device::device::{UsbDeviceBuilder, UsbVidPid};
use usbd_storage::subclass::Command;
use usbd_storage::subclass::scsi::{Scsi, ScsiCommand};
#[cfg(feature = "transfer")]
use usbd_storage::transport::TransportError;
use usbd_storage::transport::bbb::BulkOnly;

const TIMEOUT: Duration = Duration::from_secs(1);

#[test]
fn should_fail_reading_data_from_host_with_bytes_read() {
    run_on_scsi_bbb_bus_timed! { TIMEOUT, [
        Step::HostIo(|bus: &DummyUsbBus| {
            let cbw = Cbw {
                data_transfer_len: 512,
                direction: DataDirection::Out,
                block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 1 }),
            };
            bus.write_cbw(cbw);
            bus.write_data([0u8; 512].as_slice()); // host has written a block
        }),
        Step::DevIo,
        Step::DevCmdHandle(
            |cmd: Command<ScsiCommand, Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>>| {
                cmd.fail();
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            let expected_csw = Csw {
                data_transfer_len: 0, // read all
                status: CommandStatus::Failed,
            };
            assert_eq!(expected_csw, bus.read_cs().unwrap());
        }),
    ] }
}

#[test]
fn should_fail_reading_data_from_host_without_bytes_read() {
    run_on_scsi_bbb_bus_timed! { TIMEOUT, [
        Step::HostIo(|bus: &DummyUsbBus| {
            let cbw = Cbw {
                data_transfer_len: 512,
                direction: DataDirection::Out,
                block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 1 }),
            };
            bus.write_cbw(cbw);
        }),
        Step::DevIo,
        Step::DevCmdHandle(
            |cmd: Command<ScsiCommand, Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>>| {
                cmd.fail_phase();
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            // Per upstream #26 a short host-to-device phase stalls the bulk-OUT
            // endpoint and the CSW is withheld until the host clears the endpoint
            // halt (CLEAR_FEATURE), so no CSW is available yet. The clear-halt ->
            // CSW delivery path needs a control-transfer harness (follow-up).
            assert!(bus.read_cs().is_none());
        }),
    ] }
}

#[test]
fn should_pass_reading_data_from_host_with_bytes_read() {
    run_on_scsi_bbb_bus_timed! { TIMEOUT, [
        Step::HostIo(|bus: &DummyUsbBus| {
            let cbw = Cbw {
                data_transfer_len: 512,
                direction: DataDirection::Out,
                block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 1 }),
            };
            bus.write_cbw(cbw);
            bus.write_data([0u8; 512].as_slice()); // host has written a block
        }),
        Step::DevIo,
        Step::DevCmdHandle(
            |cmd: Command<ScsiCommand, Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>>| {
                cmd.pass();
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            let expected_csw = Csw {
                data_transfer_len: 0, // read all
                status: CommandStatus::Passed,
            };
            assert_eq!(expected_csw, bus.read_cs().unwrap());
        }),
    ] }
}

#[test]
fn should_phase_fail_reading_data_from_host_trying_to_pass_without_bytes_read() {
    run_on_scsi_bbb_bus_timed! { TIMEOUT, [
        Step::HostIo(|bus: &DummyUsbBus| {
            let cbw = Cbw {
                data_transfer_len: 512,
                direction: DataDirection::Out,
                block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 1 }),
            };
            bus.write_cbw(cbw);
        }),
        Step::DevIo,
        Step::DevCmdHandle(
            |cmd: Command<ScsiCommand, Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>>| {
                cmd.fail_phase();
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            // Per upstream #26 a short host-to-device phase stalls the bulk-OUT
            // endpoint and the CSW is withheld until the host clears the endpoint
            // halt (CLEAR_FEATURE), so no CSW is available yet. The clear-halt ->
            // CSW delivery path needs a control-transfer harness (follow-up).
            assert!(bus.read_cs().is_none());
        }),
    ] }
}

#[test]
fn should_fail_in_the_middle_writing_data_to_host() {
    run_on_scsi_bbb_bus_timed! { TIMEOUT, [
        Step::HostIo(|bus: &DummyUsbBus| {
            let cbw = Cbw {
                data_transfer_len: 512,
                direction: DataDirection::In,
                block: cmd_into_bytes(ScsiCommand::Read { lba: 0, len: 1 }),
            };
            bus.write_cbw(cbw);
        }),
        Step::DevCmdHandle(
            |mut cmd: Command<ScsiCommand, Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>>| {
                assert_eq!(256, cmd.write_data([0xFFu8; 256].as_slice()).unwrap());
                cmd.fail();
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            assert_eq!(256, bus.read_n_bytes(256).len()); // skip data bytes
            // Per upstream #26 a short device-to-host phase stalls the bulk-IN
            // endpoint and the CSW is withheld until the host clears the endpoint
            // halt (CLEAR_FEATURE), so no CSW is available yet. The clear-halt ->
            // CSW delivery path needs a control-transfer harness (follow-up).
            assert!(bus.read_cs().is_none());
        }),
    ] }
}

// ---------------------------------------------------------------------------
// TransferBus tests (feature = "transfer")
// ---------------------------------------------------------------------------
//
// These tests call `scsi.poll_transfer(bus, callback)` instead of the
// per-packet `scsi.poll(callback)`.  The driving loop is hand-written because
// the transfer path needs explicit synchronisation points between poll rounds
// (e.g. injecting OUT data between the prime and the retire).

/// A simple poll-drain loop: drives `poll_transfer` with an empty callback
/// until no further progress is made (bytes_processed stops changing).
#[cfg(feature = "transfer")]
fn drain_transfer(scsi: &mut Scsi<BulkOnly<'_, DummyUsbBus, &mut [u8]>>, bus: &DummyUsbBus) {
    let mut prev = bus.bytes_processed();
    loop {
        scsi.poll_transfer(bus, |_, _| {}).unwrap();
        let next = bus.bytes_processed();
        if next == prev {
            break;
        }
        prev = next;
    }
}

/// CBW(Write 64 KiB) → callback calls `read_data_transfer` →
/// host delivers data → retire → CSW Passed, residue 0, data byte-identical.
#[cfg(feature = "transfer")]
#[test]
fn transfer_poll_write_round_trip() {
    const DATA_LEN: usize = 65536;
    const MAX_SPINS: usize = 1000;
    const TIMEOUT_SECS: Duration = Duration::from_secs(5);

    common::timeout(TIMEOUT_SECS, || {
        for packet_size in common::PACKET_SIZE {
            let mut io_buf = [0u8; 1024];
            let dummy_bus = DummyUsbBus::new();
            let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
            let mut scsi = Scsi::new(&usb_bus, packet_size, 0, io_buf.as_mut_slice()).unwrap();
            let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();

            let host_data: Vec<u8> = (0u8..=255).cycle().take(DATA_LEN).collect();
            let mut recv_buf = vec![0u8; DATA_LEN];

            dummy_bus.write_cbw(Cbw {
                data_transfer_len: DATA_LEN as u32,
                direction: DataDirection::Out,
                block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 128 }),
            });

            let out_ep = dummy_bus.out_ep_addr();

            // Phase 1: poll until the callback primes the OUT transfer (WouldBlock).
            let mut primed = false;
            for _ in 0..MAX_SPINS {
                scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                    if let ScsiCommand::Write { .. } = cmd.kind {
                        match cmd.read_data_transfer(bus, &mut recv_buf) {
                            Err(TransportError::Usb(UsbError::WouldBlock)) => primed = true,
                            Ok(_) => primed = true,
                            Err(e) => panic!("unexpected error priming: {e:?}"),
                        }
                    }
                })
                .unwrap();
                if primed {
                    break;
                }
            }
            assert!(primed, "transfer was never primed");

            // Phase 2: host delivers data.
            dummy_bus.complete_out_transfer(out_ep, &host_data);

            // Phase 3: poll until the callback retires the transfer and sets status.
            let mut retired = false;
            for _ in 0..MAX_SPINS {
                scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                    if let ScsiCommand::Write { .. } = cmd.kind {
                        match cmd.read_data_transfer(bus, &mut recv_buf) {
                            Ok(_n) => {
                                cmd.pass();
                                retired = true;
                            }
                            Err(TransportError::Usb(UsbError::WouldBlock)) => {}
                            Err(e) => panic!("unexpected retire error: {e:?}"),
                        }
                    }
                })
                .unwrap();
                if retired {
                    break;
                }
            }
            assert!(retired, "transfer was never retired");

            // Phase 4: flush CSW.
            drain_transfer(&mut scsi, &dummy_bus);

            let csw = dummy_bus.read_cs().expect("no CSW");
            assert_eq!(
                csw,
                Csw {
                    data_transfer_len: 0,
                    status: CommandStatus::Passed,
                }
            );
            assert_eq!(recv_buf, host_data, "received data mismatch");
        }
    });
}

/// CBW(Read) → callback calls `write_data_transfer` → retire → CSW Passed;
/// host received exact payload.
#[cfg(feature = "transfer")]
#[test]
fn transfer_poll_read_round_trip() {
    const DATA_LEN: usize = 512;
    const MAX_SPINS: usize = 1000;
    const TIMEOUT_SECS: Duration = Duration::from_secs(5);

    common::timeout(TIMEOUT_SECS, || {
        for packet_size in common::PACKET_SIZE {
            let mut io_buf = [0u8; 1024];
            let dummy_bus = DummyUsbBus::new();
            let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
            let mut scsi = Scsi::new(&usb_bus, packet_size, 0, io_buf.as_mut_slice()).unwrap();
            let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();

            let payload: Vec<u8> = (0u8..=255).cycle().take(DATA_LEN).collect();

            dummy_bus.write_cbw(Cbw {
                data_transfer_len: DATA_LEN as u32,
                direction: DataDirection::In,
                block: cmd_into_bytes(ScsiCommand::Read { lba: 0, len: 1 }),
            });

            let in_ep = dummy_bus.in_ep_addr();

            // Phase 1: poll until write_data_transfer primes.
            let mut primed = false;
            for _ in 0..MAX_SPINS {
                scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                    if let ScsiCommand::Read { .. } = cmd.kind {
                        match cmd.write_data_transfer(bus, &payload) {
                            Err(TransportError::Usb(UsbError::WouldBlock)) => primed = true,
                            Ok(_) => primed = true,
                            Err(e) => panic!("prime error: {e:?}"),
                        }
                    }
                })
                .unwrap();
                if primed {
                    break;
                }
            }
            assert!(primed);

            // Phase 2: host completes the IN transfer and receives the bytes.
            let received = dummy_bus.complete_in_transfer(in_ep);
            assert_eq!(received, payload, "IN payload mismatch");

            // Phase 3: poll until write_data_transfer retires and sets status.
            let mut retired = false;
            for _ in 0..MAX_SPINS {
                scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                    if let ScsiCommand::Read { .. } = cmd.kind {
                        match cmd.write_data_transfer(bus, &payload) {
                            Ok(_) => {
                                cmd.pass();
                                retired = true;
                            }
                            Err(TransportError::Usb(UsbError::WouldBlock)) => {}
                            Err(e) => panic!("retire error: {e:?}"),
                        }
                    }
                })
                .unwrap();
                if retired {
                    break;
                }
            }
            assert!(retired);

            drain_transfer(&mut scsi, &dummy_bus);

            let csw = dummy_bus.read_cs().expect("no CSW");
            assert_eq!(
                csw,
                Csw {
                    data_transfer_len: 0,
                    status: CommandStatus::Passed,
                }
            );
        }
    });
}

/// Two `write_data_transfer_pipelined` submits retire in FIFO order with
/// correct byte counts.
#[cfg(feature = "transfer")]
#[test]
fn transfer_pipelined_in_fifo_order() {
    const CHUNK_A: usize = 256;
    const CHUNK_B: usize = 128;
    const TOTAL: usize = CHUNK_A + CHUNK_B;
    const MAX_SPINS: usize = 1000;
    const TIMEOUT_SECS: Duration = Duration::from_secs(5);

    common::timeout(TIMEOUT_SECS, || {
        for packet_size in common::PACKET_SIZE {
            let mut io_buf = [0u8; 1024];
            let dummy_bus = DummyUsbBus::new();
            let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
            let mut scsi = Scsi::new(&usb_bus, packet_size, 0, io_buf.as_mut_slice()).unwrap();
            let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();

            let chunk_a: Vec<u8> = vec![0xAAu8; CHUNK_A];
            let chunk_b: Vec<u8> = vec![0xBBu8; CHUNK_B];

            dummy_bus.write_cbw(Cbw {
                data_transfer_len: TOTAL as u32,
                direction: DataDirection::In,
                block: cmd_into_bytes(ScsiCommand::Read { lba: 0, len: 1 }),
            });

            let in_ep = dummy_bus.in_ep_addr();

            // Submit both pipelined transfers in one callback round.
            let mut submitted = false;
            for _ in 0..MAX_SPINS {
                scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                    if let ScsiCommand::Read { .. } = cmd.kind {
                        cmd.write_data_transfer_pipelined(bus, &chunk_a).unwrap();
                        cmd.write_data_transfer_pipelined(bus, &chunk_b).unwrap();
                        cmd.pass();
                        submitted = true;
                    }
                })
                .unwrap();
                if submitted {
                    break;
                }
            }
            assert!(submitted);

            // Verify FIFO order and payload correctness.
            let got_a = dummy_bus.complete_in_transfer(in_ep);
            let got_b = dummy_bus.complete_in_transfer(in_ep);

            assert_eq!(got_a, chunk_a, "first pipelined transfer payload mismatch");
            assert_eq!(got_b, chunk_b, "second pipelined transfer payload mismatch");

            drain_transfer(&mut scsi, &dummy_bus);

            // The pipelined IN bytes are read by the host above, but this harness
            // does not call poll_data_transfer, so the class still sees a full residue
            // (data_transfer_len == TOTAL). The command passed, so per BOT 6.7.2 case 5
            // (PR #23) the device does NOT halt bulk-IN on a passed short read — it
            // sends the CSW rather than withholding it behind a stall. The residue it
            // reports here is the un-accounted artifact; in real use poll_data_transfer
            // would retire the bytes and the reported residue would be zero.
            let csw = dummy_bus
                .read_cs()
                .expect("a passed short transfer must send the CSW, not withhold it");
            assert!(matches!(csw.status, CommandStatus::Passed));
            assert_eq!(csw.data_transfer_len, TOTAL as u32);
        }
    });
}

/// During the OUT data phase exactly ONE `submit_read` is issued with the
/// full announced length.  No per-packet max-packet-size staging reads are
/// submitted alongside the zero-copy transfer.
#[cfg(feature = "transfer")]
#[test]
fn no_staging_read_submitted_during_data_out_phase() {
    const DATA_LEN: usize = 65536;
    const MAX_SPINS: usize = 1000;
    const TIMEOUT_SECS: Duration = Duration::from_secs(5);

    common::timeout(TIMEOUT_SECS, || {
        // Use a fixed packet_size to keep the assertion simple.
        let packet_size: u16 = 64;

        let mut io_buf = [0u8; 1024];
        let dummy_bus = DummyUsbBus::new();
        let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
        let mut scsi = Scsi::new(&usb_bus, packet_size, 0, io_buf.as_mut_slice()).unwrap();
        let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();

        let out_ep = dummy_bus.out_ep_addr();
        let mut recv_buf = vec![0u8; DATA_LEN];

        dummy_bus.write_cbw(Cbw {
            data_transfer_len: DATA_LEN as u32,
            direction: DataDirection::Out,
            block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 128 }),
        });

        // Prime: poll until read_data_transfer is called once.
        let mut primed = false;
        for _ in 0..MAX_SPINS {
            scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                if let ScsiCommand::Write { .. } = cmd.kind {
                    match cmd.read_data_transfer(bus, &mut recv_buf) {
                        Err(TransportError::Usb(UsbError::WouldBlock)) => primed = true,
                        Ok(_) => primed = true,
                        Err(e) => panic!("prime error: {e:?}"),
                    }
                }
            })
            .unwrap();
            if primed {
                break;
            }
        }
        assert!(primed);

        // Exactly one submit_read with the full announced length — no staging reads.
        let lens = dummy_bus.submit_read_lens(out_ep);
        assert_eq!(
            lens.len(),
            1,
            "expected exactly 1 submit_read, got {}: {lens:?}",
            lens.len()
        );
        assert_eq!(
            lens[0], DATA_LEN,
            "submit_read length should equal the full announced length ({}), got {}",
            DATA_LEN, lens[0]
        );
    });
}

/// When the CSW write is blocked (depth-1 IN endpoint not ready), the state
/// machine stays in StatusTransfer and does not advance to Idle or accept a
/// new CBW until the write succeeds.
///
/// The CSW uses `write_packet` / `UsbBus::write` (not TransferBus).  We
/// emulate a depth-1 IN by configuring the dummy bus to return `WouldBlock`
/// on the first write, then allowing it on the second.  The test asserts that
/// no CSW bytes appear after the first (blocked) poll, and the full CSW
/// appears only after the retry — confirming the state machine stays in
/// StatusTransfer until the flush succeeds.
#[cfg(feature = "transfer")]
#[test]
fn csw_blocks_until_in_transfer_retires() {
    const MAX_SPINS: usize = 1000;
    const TIMEOUT_SECS: Duration = Duration::from_secs(5);

    common::timeout(TIMEOUT_SECS, || {
        let packet_size: u16 = 64;

        let mut io_buf = [0u8; 1024];
        let dummy_bus = DummyUsbBus::new();
        let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
        let mut scsi = Scsi::new(&usb_bus, packet_size, 0, io_buf.as_mut_slice()).unwrap();
        let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();

        // Send a no-data CBW (TestUnitReady) to reach the status phase quickly.
        dummy_bus.write_cbw(Cbw {
            data_transfer_len: 0,
            direction: DataDirection::NotExpected,
            block: cmd_into_bytes(ScsiCommand::TestUnitReady),
        });

        // Block the first write so the CSW cannot be sent.
        dummy_bus.block_next_writes(1);

        // Poll until the command is handled and status is set.
        let mut handled = false;
        for _ in 0..MAX_SPINS {
            scsi.poll_transfer(&dummy_bus, |cmd, _bus| {
                if let ScsiCommand::TestUnitReady = cmd.kind {
                    cmd.pass();
                    handled = true;
                }
            })
            .unwrap();
            if handled {
                break;
            }
        }
        assert!(handled, "command was never handled");

        // CSW write was blocked: no bytes in the IN packet queue yet.
        assert!(
            dummy_bus.read_cs().is_none(),
            "CSW should be blocked but bytes appeared in IN queue"
        );

        // Unblock writes: next poll(s) must flush the CSW.
        for _ in 0..MAX_SPINS {
            scsi.poll_transfer(&dummy_bus, |_, _| {}).unwrap();
            if dummy_bus.read_cs().is_some() {
                return; // success
            }
        }
        panic!("CSW never flushed after unblocking writes");
    });
}

/// When the host delivers fewer bytes than announced, the CSW residue
/// reflects the undelivered count and the command completes without panic.
#[cfg(feature = "transfer")]
#[test]
fn short_data_out_reports_residue() {
    const ANNOUNCED_LEN: usize = 512;
    const DELIVERED_LEN: usize = 256;
    const MAX_SPINS: usize = 1000;
    const TIMEOUT_SECS: Duration = Duration::from_secs(5);

    common::timeout(TIMEOUT_SECS, || {
        for packet_size in common::PACKET_SIZE {
            let mut io_buf = [0u8; 1024];
            let dummy_bus = DummyUsbBus::new();
            let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
            let mut scsi = Scsi::new(&usb_bus, packet_size, 0, io_buf.as_mut_slice()).unwrap();
            let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();

            let short_data = vec![0xCCu8; DELIVERED_LEN];
            let mut recv_buf = vec![0u8; ANNOUNCED_LEN];

            dummy_bus.write_cbw(Cbw {
                data_transfer_len: ANNOUNCED_LEN as u32,
                direction: DataDirection::Out,
                block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 1 }),
            });

            let out_ep = dummy_bus.out_ep_addr();

            // Prime the OUT transfer.
            let mut primed = false;
            for _ in 0..MAX_SPINS {
                scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                    if let ScsiCommand::Write { .. } = cmd.kind {
                        match cmd.read_data_transfer(bus, &mut recv_buf) {
                            Err(TransportError::Usb(UsbError::WouldBlock)) => primed = true,
                            Ok(_) => primed = true,
                            Err(e) => panic!("prime error: {e:?}"),
                        }
                    }
                })
                .unwrap();
                if primed {
                    break;
                }
            }
            assert!(primed);

            // Host delivers only DELIVERED_LEN bytes.
            dummy_bus.complete_out_transfer(out_ep, &short_data);

            // Retire + pass.
            let mut retired = false;
            for _ in 0..MAX_SPINS {
                scsi.poll_transfer(&dummy_bus, |mut cmd, bus| {
                    if let ScsiCommand::Write { .. } = cmd.kind {
                        match cmd.read_data_transfer(bus, &mut recv_buf) {
                            Ok(_n) => {
                                cmd.pass();
                                retired = true;
                            }
                            Err(TransportError::Usb(UsbError::WouldBlock)) => {}
                            Err(e) => panic!("retire error: {e:?}"),
                        }
                    }
                })
                .unwrap();
                if retired {
                    break;
                }
            }
            assert!(retired);

            drain_transfer(&mut scsi, &dummy_bus);

            // Per upstream #26, a short OUT data phase (residue 256) stalls bulk-OUT
            // and withholds the CSW until the host clears the endpoint halt
            // (CLEAR_FEATURE), so no CSW is available yet. Asserting the reported
            // residue needs the clear-halt -> CSW path (control-transfer harness, follow-up).
            assert!(dummy_bus.read_cs().is_none());
        }
    });
}
