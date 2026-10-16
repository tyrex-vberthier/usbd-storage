mod common;

use crate::common::Step;
use crate::common::bbb::{Cbw, CommandStatus, Csw, DataDirection, DummyUsbBus, setup};
use crate::common::scsi::cmd_into_bytes;
use std::time::Duration;
use usb_device::bus::UsbBusAllocator;
use usb_device::class::UsbClass;
use usb_device::device::{UsbDeviceBuilder, UsbVidPid};
use usbd_storage::subclass::Command;
use usbd_storage::subclass::scsi::{Scsi, ScsiCommand};
use usbd_storage::transport::bbb::BulkOnly;

const TIMEOUT: Duration = Duration::from_secs(1);

/// A malformed CBW must not reach the subclass.
///
/// Spec. 6.6.1 makes an invalid CBW terminal until a Reset Recovery, so there is no
/// command to dispatch. When `get_command` still reported one, the block came from an
/// unpopulated `CommandBlockWrapper`; on the first CBW after power-up that is an empty
/// CDB, and `scsi::parse_cb` indexes `cb[0]` -- an index-out-of-bounds panic in release
/// builds, reachable from a single 31-byte packet on the wire.
#[test]
fn invalid_first_cbw_does_not_reach_the_subclass() {
    /*
    let mut io_buf = [0u8; 1024];
    let dummy_bus = DummyUsbBus::new();
    let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
    let mut scsi = Scsi::new(&usb_bus, 64, 0, io_buf.as_mut_slice()).unwrap();
    let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();

    let mut bad = Cbw {
        data_transfer_len: 0,
        direction: DataDirection::NotExpected,
        block: vec![0x12],
    }
    .into_bytes();
    bad[0] ^= 0xFF; // corrupt dCBWSignature
    dummy_bus.write_data(bad.as_slice());

    scsi.poll(); // reads the CBW, enters the terminal invalid state

    let mut dispatched = false;
    scsi.poll_command(|_cmd| {
        dispatched = true;
        Ok(())
    })
    .unwrap();

    assert!(!dispatched, "an invalid CBW was dispatched to the subclass");
    */

    run_on_scsi_bbb_bus_timed! { TIMEOUT, [
        Step::HostIo(|bus: &DummyUsbBus| {
            let bad_cbw = Cbw {
                data_transfer_len: 0,
                direction: DataDirection::NotExpected,
                block: vec![0x12],
            };

            let mut bad_cbw_bytes = bad_cbw.into_bytes();
            bad_cbw_bytes[0] ^= 0xFF; // corrupt dCBWSignature

            bus.write_data(&bad_cbw_bytes);
        }),
        Step::DevIo,
        Step::DevAssertNoCommand,
    ]}
}

#[test]
fn should_fail_reading_data_from_host_with_bytes_processed() {
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
                cmd.fail(512); // processed all data
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            let expected_csw = Csw {
                data_transfer_len: 0, // processed all data
                status: CommandStatus::Failed,
            };
            assert_eq!(expected_csw, bus.read_cs().unwrap());
        }),
    ] }
}

#[test]
fn should_fail_reading_data_from_host_without_bytes_processed() {
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
                cmd.fail_phase();
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            let expected_csw = Csw {
                data_transfer_len: 512, // no data has been processed
                status: CommandStatus::PhaseError,
            };
            assert_eq!(expected_csw, bus.read_cs().unwrap());
        }),
    ] }
}

#[test]
fn should_pass_reading_data_from_host_with_bytes_processed() {
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
                cmd.pass(512); // processed all data
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            let expected_csw = Csw {
                data_transfer_len: 0, // processed all data
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
            bus.write_data([0u8; 512].as_slice()); // host has written a block
        }),
        Step::DevIo,
        Step::DevCmdHandle(
            |cmd: Command<ScsiCommand, Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>>| {
                cmd.fail_phase();
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            let expected_csw = Csw {
                data_transfer_len: 512,
                status: CommandStatus::PhaseError,
            };
            assert_eq!(expected_csw, bus.read_cs().unwrap());
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
        Step::DevIo,
        Step::DevCmdHandle(
            |mut cmd: Command<ScsiCommand, Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>>| {
                assert_eq!(256, cmd.write_data([0xFFu8; 256].as_slice()).unwrap());
                cmd.fail(256); // processed some data
            },
        ),
        Step::DevIo,
        Step::HostIo(|bus: &DummyUsbBus| {
            assert_eq!(512, bus.read_n_bytes(512).len()); // skip all data bytes
            let expected_csw = Csw {
                data_transfer_len: 256, // processed part
                status: CommandStatus::Failed,
            };
            assert_eq!(expected_csw, bus.read_cs().unwrap());
        }),
    ] }
}

/// Spec. 3.1 and 3.2 address both Bulk-Only class requests to the Mass Storage
/// interface, in `wIndex`. usb-device offers every control request to every class, so
/// on a composite device the requests meant for a sibling interface reach this class
/// too. Answering one steals it from the class it was meant for, and a Mass Storage
/// Reset honoured that way also drops the command in flight.
#[test]
fn class_requests_for_another_interface_are_left_alone() {
    let mut io_buf = [0u8; 1024];
    let bus = DummyUsbBus::new();
    let alloc = UsbBusAllocator::new(bus.clone());
    let mut scsi = Scsi::new(&alloc, 64, 0, io_buf.as_mut_slice()).unwrap();
    let theirs = u16::from(u8::from(alloc.interface()));
    let ours = 0;
    assert_eq!(theirs, 1, "Scsi should hold the first interface");
    let mut device = UsbDeviceBuilder::new(&alloc, UsbVidPid(0xabcd, 0xabcd)).build();

    let get_max_lun = |index| setup(0xA1, 0xFE, 0, index, 1);
    let reset = |index| setup(0x21, 0xFF, 0, index, 0);

    assert_eq!(
        bus.control(&mut device, &mut scsi, get_max_lun(theirs)),
        None,
        "GET MAX LUN for another interface should be refused"
    );
    assert_eq!(
        bus.control(&mut device, &mut scsi, get_max_lun(ours)),
        Some(vec![0]),
        "GET MAX LUN for this interface should be answered"
    );

    bus.write_cbw(Cbw {
        data_transfer_len: 0,
        direction: DataDirection::NotExpected,
        block: cmd_into_bytes(ScsiCommand::TestUnitReady),
    });
    drive(&bus, &mut scsi);
    assert!(has_command(&mut scsi), "the CBW should be in flight");

    assert_eq!(
        bus.control(&mut device, &mut scsi, reset(theirs)),
        None,
        "a Mass Storage Reset for another interface should be refused"
    );
    assert!(
        has_command(&mut scsi),
        "a Mass Storage Reset for another interface should leave the command in flight"
    );

    assert_eq!(
        bus.control(&mut device, &mut scsi, reset(ours)),
        Some(vec![]),
        "a Mass Storage Reset for this interface should be accepted"
    );
    assert!(
        !has_command(&mut scsi),
        "a Mass Storage Reset for this interface should drop the command in flight"
    );
}

/// A firmware that filters or sends requests per interface reads the number the class
/// answers to from `interface()`, so it must be the one `wIndex` has to carry. Two
/// sibling interfaces around the class keep a hard-coded 0 or 1 from passing.
#[test]
fn interface_is_the_one_the_class_answers_to() {
    let mut io_buf = [0u8; 1024];
    let bus = DummyUsbBus::new();
    let alloc = UsbBusAllocator::new(bus.clone());
    let before = u8::from(alloc.interface());
    let mut scsi = Scsi::new(&alloc, 64, 0, io_buf.as_mut_slice()).unwrap();
    let after = u8::from(alloc.interface());
    let mut device = UsbDeviceBuilder::new(&alloc, UsbVidPid(0xabcd, 0xabcd)).build();

    let ours = u8::from(scsi.interface());
    assert_eq!(
        (before, ours, after),
        (0, 1, 2),
        "the class should hold the interface allocated between its siblings"
    );

    let get_max_lun = |index: u8| setup(0xA1, 0xFE, 0, u16::from(index), 1);
    assert_eq!(
        bus.control(&mut device, &mut scsi, get_max_lun(ours)),
        Some(vec![0]),
        "GET MAX LUN for interface() should be answered"
    );
    for other in [before, after] {
        assert_eq!(
            bus.control(&mut device, &mut scsi, get_max_lun(other)),
            None,
            "GET MAX LUN for sibling interface {other} should be refused"
        );
    }
}

/// [`interface_is_the_one_the_class_answers_to`], for UFI.
#[cfg(feature = "ufi")]
#[test]
fn ufi_interface_is_the_one_the_class_answers_to() {
    use usbd_storage::subclass::ufi::Ufi;

    let mut io_buf = [0u8; 1024];
    let bus = DummyUsbBus::new();
    let alloc = UsbBusAllocator::new(bus.clone());
    let before = u8::from(alloc.interface());
    let mut ufi = Ufi::new(&alloc, 64, io_buf.as_mut_slice()).unwrap();
    let after = u8::from(alloc.interface());
    let mut device = UsbDeviceBuilder::new(&alloc, UsbVidPid(0xabcd, 0xabcd)).build();

    let ours = u8::from(ufi.interface());
    assert_eq!(
        (before, ours, after),
        (0, 1, 2),
        "the class should hold the interface allocated between its siblings"
    );

    let get_max_lun = |index: u8| setup(0xA1, 0xFE, 0, u16::from(index), 1);
    assert_eq!(
        bus.control(&mut device, &mut ufi, get_max_lun(ours)),
        Some(vec![0]),
        "GET MAX LUN for interface() should be answered"
    );
    for other in [before, after] {
        assert_eq!(
            bus.control(&mut device, &mut ufi, get_max_lun(other)),
            None,
            "GET MAX LUN for sibling interface {other} should be refused"
        );
    }
}

/// The addresses of the endpoint descriptors in a configuration descriptor, in order.
fn described_endpoints(config: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    let mut at = 0;
    while let Some(&len) = config.get(at) {
        let descriptor = &config[at..at + usize::from(len)];
        if descriptor[1] == 0x05 {
            out.push(descriptor[2]);
        }
        at += usize::from(len);
    }
    out
}

/// A firmware resets the data toggles of the endpoints `endpoint_addresses` returns on
/// `SET_INTERFACE`, so they must be the ones the host sees in the descriptors.
#[test]
fn endpoint_addresses_are_those_the_descriptors_carry() {
    let mut io_buf = [0u8; 1024];
    let bus = DummyUsbBus::new();
    let alloc = UsbBusAllocator::new(bus.clone());
    let mut scsi = Scsi::new(&alloc, 64, 0, io_buf.as_mut_slice()).unwrap();
    let mut device = UsbDeviceBuilder::new(&alloc, UsbVidPid(0xabcd, 0xabcd)).build();

    let config = bus
        .control(&mut device, &mut scsi, setup(0x80, 6, 0x0200, 0, 255))
        .expect("GET_DESCRIPTOR should be answered");

    let [bulk_in, bulk_out] = scsi.endpoint_addresses().map(u8::from);
    assert_eq!(
        described_endpoints(&config),
        [bulk_in, bulk_out],
        "bulk IN then bulk OUT, as the endpoint descriptors list them"
    );
    assert_ne!(bulk_in, bulk_out, "the two endpoints are distinct");
}

/// [`endpoint_addresses_are_those_the_descriptors_carry`], for UFI.
#[cfg(feature = "ufi")]
#[test]
fn ufi_endpoint_addresses_are_those_the_descriptors_carry() {
    use usbd_storage::subclass::ufi::Ufi;

    let mut io_buf = [0u8; 1024];
    let bus = DummyUsbBus::new();
    let alloc = UsbBusAllocator::new(bus.clone());
    let mut ufi = Ufi::new(&alloc, 64, io_buf.as_mut_slice()).unwrap();
    let mut device = UsbDeviceBuilder::new(&alloc, UsbVidPid(0xabcd, 0xabcd)).build();

    let config = bus
        .control(&mut device, &mut ufi, setup(0x80, 6, 0x0200, 0, 255))
        .expect("GET_DESCRIPTOR should be answered");

    let [bulk_in, bulk_out] = ufi.endpoint_addresses().map(u8::from);
    assert_eq!(
        described_endpoints(&config),
        [bulk_in, bulk_out],
        "bulk IN then bulk OUT, as the endpoint descriptors list them"
    );
    assert_ne!(bulk_in, bulk_out, "the two endpoints are distinct");
}

/// Drive the device until it has no IO left to do
fn drive(bus: &DummyUsbBus, scsi: &mut Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>) {
    let mut bytes_processed = bus.bytes_processed();
    loop {
        scsi.poll();
        let new = bus.bytes_processed();
        if new == bytes_processed {
            break;
        }
        bytes_processed = new;
    }
}

/// Whether a command waits for the subclass, which leaves it in flight
fn has_command(scsi: &mut Scsi<BulkOnly<DummyUsbBus, &mut [u8]>>) -> bool {
    let mut seen = false;
    scsi.poll_command(|_| {
        seen = true;
        Ok(())
    })
    .unwrap();
    seen
}

#[cfg(feature = "transfer")]
mod zero_copy {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use usb_device::UsbError;
    use usb_device::endpoint::EndpointAddress;
    use usbd_storage::transfer::{Rejected, Retired, TransferBus};

    struct Pending {
        ep: EndpointAddress,
        buf: &'static mut [u8],
        len: usize,
        out: bool,
        done: bool,
    }

    /// A [`TransferBus`] whose transfers finish when the test says so.
    #[derive(Default)]
    struct MockTransfers {
        queue: RefCell<VecDeque<Pending>>,
    }

    impl MockTransfers {
        fn submit(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
            out: bool,
        ) -> Result<(), Rejected> {
            self.queue.borrow_mut().push_back(Pending {
                ep,
                buf,
                len,
                out,
                done: false,
            });
            Ok(())
        }

        /// Finishes the oldest transfer: an OUT one receives `data`, an IN one returns
        /// the bytes it put on the wire.
        fn finish(&self, data: &[u8]) -> Vec<u8> {
            let mut queue = self.queue.borrow_mut();
            let p = queue.front_mut().expect("no transfer queued");
            p.done = true;
            if p.out {
                p.buf[..data.len()].copy_from_slice(data);
                p.len = data.len();
                Vec::new()
            } else {
                p.buf[..p.len].to_vec()
            }
        }
    }

    impl TransferBus for MockTransfers {
        fn submit_write(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
        ) -> Result<(), Rejected> {
            self.submit(ep, buf, len, false)
        }

        fn submit_read(
            &self,
            ep: EndpointAddress,
            buf: &'static mut [u8],
            len: usize,
        ) -> Result<(), Rejected> {
            self.submit(ep, buf, len, true)
        }

        fn poll_transfer(&self, ep: EndpointAddress) -> Option<Retired> {
            let mut queue = self.queue.borrow_mut();
            if !queue.front().is_some_and(|p| p.done && p.ep == ep) {
                return None;
            }
            let p = queue.pop_front()?;
            Some(Retired {
                buf: p.buf,
                result: Ok::<usize, UsbError>(p.len),
            })
        }
    }

    fn dma(len: usize) -> &'static mut [u8] {
        Box::leak(vec![0u8; len].into_boxed_slice())
    }

    /// Polls the device until it has put a CSW on the bus.
    /// Polls the device until it stops moving bytes, then reads the CSW as the host would.
    fn csw(scsi: &mut Scsi<BulkOnly<'_, DummyUsbBus, &mut [u8]>>, bus: &DummyUsbBus) -> Csw {
        let mut processed = bus.bytes_processed();
        loop {
            scsi.poll();
            let now = bus.bytes_processed();
            if now == processed {
                break;
            }
            processed = now;
        }
        bus.read_cs().expect("no CSW")
    }

    #[test]
    fn write_and_read_without_the_io_buffer() {
        common::timeout(TIMEOUT, || {
            for packet_size in common::PACKET_SIZE {
                let mut io_buf = [0u8; 1024];
                let dummy_bus = DummyUsbBus::new();
                let usb_bus = UsbBusAllocator::new(dummy_bus.clone());
                let mut scsi = Scsi::new(&usb_bus, packet_size, 0, io_buf.as_mut_slice()).unwrap();
                let _ = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0xabcd, 0xabcd)).build();
                scsi.enable_zero_copy();
                let transfers = MockTransfers::default();

                // WRITE(10): the callback submits the whole data phase, then retires it.
                dummy_bus.write_cbw(Cbw {
                    data_transfer_len: 512,
                    direction: DataDirection::Out,
                    block: cmd_into_bytes(ScsiCommand::Write { lba: 0, len: 1 }),
                });
                // The host is already sending: the transport must leave these packets
                // to the transfer the subclass is about to submit.
                dummy_bus.write_data(&[0x5A; 512]);
                for _ in 0..16 {
                    scsi.poll();
                }
                assert_eq!(
                    dummy_bus.out_bytes_read(),
                    31,
                    "ps={packet_size}: only the CBW"
                );
                let mut slot = Some(dma(512));
                let mut received = None;
                for _ in 0..256 {
                    scsi.poll();
                    let _ = scsi.poll_command(|mut cmd| {
                        assert!(matches!(cmd.kind, ScsiCommand::Write { .. }));
                        if let Some(buf) = slot.take() {
                            cmd.submit_data_out(&transfers, buf, 512).unwrap();
                            transfers.finish(&dummy_bus.take_out_data());
                        } else if let Some(retired) = cmd.poll_data_transfer(&transfers)? {
                            received = Some(retired.buf.to_vec());
                            cmd.pass(512);
                        }
                        Ok(())
                    });
                    if received.is_some() {
                        break;
                    }
                }
                assert_eq!(received, Some(vec![0x5A; 512]), "ps={packet_size}");
                assert_eq!(
                    csw(&mut scsi, &dummy_bus),
                    Csw {
                        data_transfer_len: 0,
                        status: CommandStatus::Passed,
                    },
                    "ps={packet_size}"
                );

                // READ(10): the status is set right away; the transfer is retired outside
                // the callback, which is not called again once there is a status.
                dummy_bus.write_cbw(Cbw {
                    data_transfer_len: 512,
                    direction: DataDirection::In,
                    block: cmd_into_bytes(ScsiCommand::Read { lba: 0, len: 1 }),
                });
                let mut handled = false;
                for _ in 0..256 {
                    scsi.poll();
                    let _ = scsi.poll_command(|mut cmd| {
                        let buf = dma(512);
                        buf.fill(0xA5);
                        cmd.submit_data_in(&transfers, buf, 512).unwrap();
                        cmd.pass(512);
                        handled = true;
                        Ok(())
                    });
                    if handled {
                        break;
                    }
                }
                assert!(handled, "ps={packet_size}");
                scsi.poll();
                assert!(
                    dummy_bus.read_cs().is_none(),
                    "ps={packet_size}: CSW before the data"
                );
                assert_eq!(transfers.finish(&[]), vec![0xA5; 512], "ps={packet_size}");
                let retired = scsi
                    .poll_data_transfer(&transfers)
                    .unwrap()
                    .expect("retired");
                assert_eq!(retired.result, Ok(512), "ps={packet_size}");
                assert_eq!(
                    csw(&mut scsi, &dummy_bus),
                    Csw {
                        data_transfer_len: 0,
                        status: CommandStatus::Passed,
                    },
                    "ps={packet_size}"
                );
            }
        });
    }
}
