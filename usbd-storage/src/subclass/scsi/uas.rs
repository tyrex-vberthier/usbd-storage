//! SCSI over UAS on alternate setting 1, with the Bulk-Only Transport on alternate
//! setting 0, behind the `uas` feature.

use super::{SUBCLASS_SCSI, Scsi};
use crate::CLASS_MASS_STORAGE;
use crate::fmt::trace;
use crate::transport::Transport;
use crate::transport::bbb::{BulkOnly, BulkOnlyError, TRANSPORT_BBB};
use crate::transport::uas::{TRANSPORT_UAS, Uas};
use core::borrow::BorrowMut;
use usb_device::bus::{InterfaceNumber, UsbBus, UsbBusAllocator};
use usb_device::class::{ControlIn, ControlOut, UsbClass};
use usb_device::descriptor::DescriptorWriter;
use usb_device::endpoint::EndpointAddress;

/// SCSI Mass Storage class that offers the host both BOT (alternate setting 0) and UAS
/// (alternate setting 1) on one interface.
///
/// The two bulk data endpoints belong to the BOT transport and are listed in both
/// alternate settings; only the UAS command and status pipes are extra, so the class
/// needs four bulk endpoints, not six.
///
/// [`UsbClass::poll`] drives whichever transport is active: the BOT state machine on
/// alternate setting 0, [`Uas::pump`] on alternate setting 1. A `SET_INTERFACE` resets
/// both before switching.
pub struct ScsiUas<'alloc, Bus: UsbBus, Buf: BorrowMut<[u8]>> {
    bot: Scsi<BulkOnly<'alloc, Bus, Buf>>,
    uas: Uas<'alloc, Bus>,
    active_alt: u8,
}

impl<'alloc, Bus, Buf> ScsiUas<'alloc, Bus, Buf>
where
    Bus: UsbBus + 'alloc,
    Buf: BorrowMut<[u8]>,
{
    /// Creates the class, starting on alternate setting 0.
    ///
    /// The arguments are those of [`Scsi::new`]; `buf` is the BOT transport's IO buffer.
    ///
    /// # Errors
    /// The [`BulkOnlyError`]s of [`Scsi::new`].
    ///
    /// # Panics
    /// Panics if endpoint allocation fails, as [`Scsi::new`] does.
    pub fn new(
        alloc: &'alloc UsbBusAllocator<Bus>,
        packet_size: u16,
        max_lun: u8,
        buf: Buf,
    ) -> Result<Self, BulkOnlyError> {
        let bot = Scsi::new(alloc, packet_size, max_lun, buf)?;
        let (data_in, data_out) = bot.transport.data_endpoints();
        let uas = Uas::new(alloc, packet_size, data_in.address(), data_out.address());
        Ok(Self {
            bot,
            uas,
            active_alt: 0,
        })
    }

    /// The interface number the class allocated in `new`, shared by both alternate
    /// settings.
    ///
    /// It is the `wIndex` of the Bulk-Only class requests the class answers on
    /// alternate setting 0.
    pub fn interface(&self) -> InterfaceNumber {
        self.bot.interface()
    }

    /// The active alternate setting: 0 for BOT, 1 for UAS.
    pub fn active_alt(&self) -> u8 {
        self.active_alt
    }

    /// The BOT class, while alternate setting 0 is active.
    pub fn bot(&mut self) -> Option<&mut Scsi<BulkOnly<'alloc, Bus, Buf>>> {
        (self.active_alt == 0).then_some(&mut self.bot)
    }

    /// The UAS engine, while alternate setting 1 is active.
    pub fn uas(&mut self) -> Option<&mut Uas<'alloc, Bus>> {
        (self.active_alt == 1).then_some(&mut self.uas)
    }

    /// Makes the BOT transport's OUT data phases wait for the subclass, see
    /// [`BulkOnly::enable_zero_copy`].
    pub fn enable_zero_copy(&mut self) {
        self.bot.enable_zero_copy();
    }

    /// Addresses of the shared data pipes, as `(bulk IN, bulk OUT)`.
    ///
    /// Both alternate settings list them. On a switch, transfers the previous setting
    /// left queued on them must be cancelled in the controller driver: a BOT CBW read
    /// still primed on bulk OUT would take the first packet of the first UAS data-out
    /// phase.
    pub fn data_pipe_addresses(&self) -> (EndpointAddress, EndpointAddress) {
        let (data_in, data_out) = self.bot.transport.data_endpoints();
        (data_in.address(), data_out.address())
    }
}

impl<'alloc, Bus, Buf> UsbClass<Bus> for ScsiUas<'alloc, Bus, Buf>
where
    Bus: UsbBus + 'alloc,
    Buf: BorrowMut<[u8]>,
{
    /// Alternate setting 0 reproduces [`Scsi`]'s descriptors byte for byte; alternate
    /// setting 1 follows, its endpoints in the order the Linux gadget driver `f_tcm`
    /// uses at High Speed: data in, data out, status, command, each followed by its
    /// Pipe Usage descriptor.
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        let interface = self.bot.interface;
        writer.iad(
            interface,
            1,
            CLASS_MASS_STORAGE,
            SUBCLASS_SCSI,
            TRANSPORT_BBB,
            None,
        )?;
        writer.interface(interface, CLASS_MASS_STORAGE, SUBCLASS_SCSI, TRANSPORT_BBB)?;
        self.bot.transport.get_endpoint_descriptors(writer)?;

        writer.interface_alt(
            interface,
            1,
            CLASS_MASS_STORAGE,
            SUBCLASS_SCSI,
            TRANSPORT_UAS,
            None,
        )?;
        let (data_in, data_out) = self.bot.transport.data_endpoints();
        self.uas.write_alt1_descriptors(writer, data_in, data_out)
    }

    fn get_alt_setting(&mut self, interface: InterfaceNumber) -> Option<u8> {
        (interface == self.bot.interface).then_some(self.active_alt)
    }

    fn set_alt_setting(&mut self, interface: InterfaceNumber, alternative: u8) -> bool {
        if interface != self.bot.interface || alternative > 1 {
            return false;
        }
        trace!("usb: scsi-uas: alternate setting {}", alternative);
        self.bot.transport.reset();
        self.uas.reset();
        self.active_alt = alternative;
        true
    }

    fn reset(&mut self) {
        self.bot.transport.reset();
        self.uas.reset();
        self.active_alt = 0;
    }

    /// GET MAX LUN, on alternate setting 0. Through [Scsi], which leaves a
    /// request for another interface alone.
    fn control_in(&mut self, xfer: ControlIn<Bus>) {
        if self.active_alt == 0 {
            self.bot.control_in(xfer);
        }
    }

    /// The Bulk-Only Mass Storage Reset, on alternate setting 0. Through [Scsi],
    /// which leaves a request for another interface alone.
    fn control_out(&mut self, xfer: ControlOut<Bus>) {
        if self.active_alt == 0 {
            self.bot.control_out(xfer);
        }
    }

    fn poll(&mut self) {
        if self.active_alt == 0 {
            if let Err(err) = self.bot.transport.poll() {
                trace!("usb: scsi-uas: poll: {}", err);
            }
        } else {
            self.uas.pump();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::result;
    use std::sync::{Arc, Mutex};
    use usb_device::bus::PollResult;
    use usb_device::class_prelude::EndpointType;
    use usb_device::device::{UsbDevice, UsbDeviceBuilder, UsbVidPid};
    use usb_device::{UsbDirection, UsbError};

    type TestResult = result::Result<(), Box<dyn std::error::Error>>;

    #[derive(Default)]
    struct Wire {
        /// host -> device packets, by endpoint address
        out: HashMap<u8, VecDeque<Vec<u8>>>,
        /// SETUP packets the host has queued on endpoint 0
        setup: VecDeque<[u8; 8]>,
        /// what the device wrote on endpoint 0 IN
        ep0_in: Vec<u8>,
        /// a write on endpoint 0 IN waits for its completion to be reported
        ep0_in_pending: bool,
        /// the device stalled endpoint 0, i.e. refused the request
        ep0_stalled: bool,
        next_index: usize,
    }

    #[derive(Clone, Default)]
    struct MockBus(Arc<Mutex<Wire>>);

    impl UsbBus for MockBus {
        fn alloc_ep(
            &mut self,
            ep_dir: UsbDirection,
            ep_addr: Option<EndpointAddress>,
            _ep_type: EndpointType,
            _max_packet_size: u16,
            _interval: u8,
        ) -> usb_device::Result<EndpointAddress> {
            if let Some(addr) = ep_addr {
                return Ok(addr);
            }
            let mut wire = self.0.lock().unwrap();
            wire.next_index += 1;
            Ok(EndpointAddress::from_parts(wire.next_index, ep_dir))
        }
        fn enable(&mut self) {}
        fn reset(&self) {}
        fn set_device_address(&self, _addr: u8) {}
        fn write(&self, ep: EndpointAddress, buf: &[u8]) -> usb_device::Result<usize> {
            let mut wire = self.0.lock().unwrap();
            if ep.index() == 0 {
                wire.ep0_in.extend_from_slice(buf);
                wire.ep0_in_pending = true;
            }
            Ok(buf.len())
        }
        fn read(&self, ep: EndpointAddress, buf: &mut [u8]) -> usb_device::Result<usize> {
            let mut wire = self.0.lock().unwrap();
            if ep.index() == 0 {
                return match wire.setup.pop_front() {
                    Some(setup) => {
                        buf[..8].copy_from_slice(&setup);
                        Ok(8)
                    }
                    None => Err(UsbError::WouldBlock),
                };
            }
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
        fn set_stalled(&self, ep: EndpointAddress, stalled: bool) {
            if ep.index() == 0 && stalled {
                self.0.lock().unwrap().ep0_stalled = true;
            }
        }
        fn is_stalled(&self, _ep: EndpointAddress) -> bool {
            false
        }
        fn suspend(&self) {}
        fn resume(&self) {}
        fn poll(&self) -> PollResult {
            let mut wire = self.0.lock().unwrap();
            if !wire.setup.is_empty() {
                return PollResult::Data {
                    ep_out: 0,
                    ep_in_complete: 0,
                    ep_setup: 1,
                };
            }
            if wire.ep0_in_pending {
                wire.ep0_in_pending = false;
                return PollResult::Data {
                    ep_out: 0,
                    ep_in_complete: 1,
                    ep_setup: 0,
                };
            }
            PollResult::None
        }
    }

    type Class = ScsiUas<'static, MockBus, Vec<u8>>;
    type Device = UsbDevice<'static, MockBus>;

    fn new_class() -> (MockBus, Class) {
        new_class_and_another_interface().0
    }

    fn new_class_and_another_interface() -> ((MockBus, Class), InterfaceNumber) {
        let (bus, class, other, device) = new_device();
        core::mem::forget(device);
        ((bus, class), other)
    }

    fn new_device() -> (MockBus, Class, InterfaceNumber, Device) {
        let bus = MockBus::default();
        let alloc = Box::leak(Box::new(UsbBusAllocator::new(bus.clone())));
        let class = ScsiUas::new(alloc, 64, 0, vec![0u8; 512]).unwrap();
        let other = alloc.interface();
        let device = UsbDeviceBuilder::new(alloc, UsbVidPid(0xabcd, 0xabcd))
            .composite_with_iads()
            .build();
        (bus, class, other, device)
    }

    /// Runs one control transfer the way a host would, and returns what the device
    /// answered on endpoint 0, or `None` when it refused the request.
    fn control(
        bus: &MockBus,
        device: &mut Device,
        class: &mut Class,
        setup: [u8; 8],
    ) -> Option<Vec<u8>> {
        {
            let mut wire = bus.0.lock().unwrap();
            wire.setup.push_back(setup);
            wire.ep0_in.clear();
            wire.ep0_stalled = false;
        }
        for _ in 0..64 {
            device.poll(&mut [&mut *class]);
            let wire = bus.0.lock().unwrap();
            if wire.setup.is_empty() && !wire.ep0_in_pending {
                break;
            }
        }
        let wire = bus.0.lock().unwrap();
        (!wire.ep0_stalled).then(|| wire.ep0_in.clone())
    }

    /// A SETUP packet: bmRequestType, bRequest, wValue, wIndex, wLength.
    fn setup(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
        let mut s = [0u8; 8];
        s[0] = request_type;
        s[1] = request;
        s[2..4].copy_from_slice(&value.to_le_bytes());
        s[4..6].copy_from_slice(&index.to_le_bytes());
        s[6..8].copy_from_slice(&length.to_le_bytes());
        s
    }

    fn host_sends(bus: &MockBus, ep: EndpointAddress, packet: Vec<u8>) {
        let mut wire = bus.0.lock().unwrap();
        wire.out.entry(ep.into()).or_default().push_back(packet);
    }

    /// A TEST UNIT READY CBW.
    fn cbw() -> Vec<u8> {
        let mut c = vec![0u8; 31];
        c[..4].copy_from_slice(&0x4342_5355u32.to_le_bytes());
        c[14] = 6;
        c
    }

    /// A Command IU: TEST UNIT READY for `tag` on LUN 0.
    fn command_iu(tag: u16) -> Vec<u8> {
        let mut iu = vec![0u8; 32];
        iu[0] = 0x01;
        iu[2..4].copy_from_slice(&tag.to_be_bytes());
        iu
    }

    fn bot_has_command(class: &mut Class) -> bool {
        let mut seen = false;
        if let Some(bot) = class.bot() {
            let _ = bot.poll_command(|_| {
                seen = true;
                Ok(())
            });
        }
        seen
    }

    #[test]
    fn only_alternate_settings_0_and_1_of_our_interface_are_accepted() -> TestResult {
        let ((_bus, mut class), other) = new_class_and_another_interface();
        let ours = class.bot.interface;

        assert_eq!(class.get_alt_setting(ours), Some(0), "starts on BOT");
        assert_eq!(class.get_alt_setting(other), None, "not our interface");
        assert!(!class.set_alt_setting(ours, 2), "no alternate setting 2");
        assert!(!class.set_alt_setting(other, 1), "not our interface");
        assert_eq!(class.active_alt(), 0, "refusals change nothing");

        assert!(class.set_alt_setting(ours, 1), "UAS");
        assert_eq!(class.get_alt_setting(ours), Some(1));
        assert_eq!(class.active_alt(), 1);
        Ok(())
    }

    #[test]
    fn interface_is_the_one_the_class_answers_to() -> TestResult {
        let (bus, mut class, other, mut device) = new_device();
        let ours = class.interface();

        assert!(ours != other, "a sibling interface is a different number");
        assert_eq!(class.get_alt_setting(ours), Some(0), "the class owns it");
        assert_eq!(
            control(
                &bus,
                &mut device,
                &mut class,
                setup(0xA1, 0xFE, 0, u16::from(u8::from(ours)), 1)
            ),
            Some(vec![0]),
            "GET MAX LUN for interface() is answered"
        );
        Ok(())
    }

    #[test]
    fn each_half_is_reachable_only_on_its_alternate_setting() -> TestResult {
        let (_bus, mut class) = new_class();
        let ours = class.bot.interface;

        assert!(class.bot().is_some() && class.uas().is_none(), "alt 0");
        class.set_alt_setting(ours, 1);
        assert!(class.bot().is_none() && class.uas().is_some(), "alt 1");
        Ok(())
    }

    #[test]
    fn poll_drives_the_active_transport_only() -> TestResult {
        let (bus, mut class) = new_class();
        let ours = class.bot.interface;
        let (_, bot_out) = class.data_pipe_addresses();
        let cmd_pipe = class.uas.cmd_ep.address();

        // alt 1: the UAS command pipe is read, the BOT one is left alone
        class.set_alt_setting(ours, 1);
        host_sends(&bus, bot_out, cbw());
        host_sends(&bus, cmd_pipe, command_iu(3));
        class.poll();
        assert_eq!(class.uas.table.len(), 1, "the UAS command was taken in");
        assert_eq!(
            bus.0.lock().unwrap().out[&u8::from(bot_out)].len(),
            1,
            "the CBW was left on the wire"
        );

        // alt 0: the BOT transport reads its CBW; the UAS pipe is left alone
        class.set_alt_setting(ours, 0);
        host_sends(&bus, cmd_pipe, command_iu(4));
        class.poll();
        assert!(bot_has_command(&mut class), "the CBW was taken in");
        assert_eq!(
            bus.0.lock().unwrap().out[&u8::from(cmd_pipe)].len(),
            1,
            "the Command IU was left on the wire"
        );
        Ok(())
    }

    #[test]
    fn switching_or_resetting_clears_both_transports() -> TestResult {
        let (bus, mut class) = new_class();
        let ours = class.bot.interface;
        let cmd_pipe = class.uas.cmd_ep.address();
        let (_, bot_out) = class.data_pipe_addresses();

        class.set_alt_setting(ours, 1);
        host_sends(&bus, cmd_pipe, command_iu(3));
        class.poll();
        class.set_alt_setting(ours, 1);
        assert!(class.uas.table.is_empty(), "re-selecting alt 1 clears UAS");

        class.set_alt_setting(ours, 0);
        host_sends(&bus, bot_out, cbw());
        class.poll();
        assert!(class.bot.transport.get_command().is_some(), "a BOT command");
        class.set_alt_setting(ours, 0);
        assert!(
            class.bot.transport.get_command().is_none(),
            "re-selecting alt 0 clears BOT"
        );

        class.set_alt_setting(ours, 1);
        host_sends(&bus, cmd_pipe, command_iu(5));
        class.poll();
        UsbClass::reset(&mut class);
        assert_eq!(class.active_alt(), 0, "a bus reset goes back to BOT");
        assert!(class.uas.table.is_empty(), "and clears UAS");
        Ok(())
    }

    #[test]
    fn uas_uses_the_bot_data_pipes() -> TestResult {
        let (_bus, class) = new_class();
        let (data_in, data_out) = class.data_pipe_addresses();
        assert_eq!((class.uas.data_in, class.uas.data_out), (data_in, data_out));
        assert!(data_in.is_in() && data_out.is_out(), "directions");
        Ok(())
    }

    /// Splits a configuration descriptor into (bDescriptorType, the fields after it that
    /// tell descriptors of that type apart).
    fn summary(config: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = vec![];
        let mut at = 0;
        while let Some(&len) = config.get(at) {
            let d = &config[at..at + usize::from(len)];
            let keep = match d[1] {
                0x0B => 5,        // IAD: first interface, count, class, subclass, protocol
                0x04 => 6, // interface: number, alternate, endpoints, class, subclass, protocol
                0x05 | 0x24 => 1, // endpoint address, pipe ID
                _ => 0,
            };
            out.push((d[1], d[2..2 + keep].to_vec()));
            at += usize::from(len);
        }
        out
    }

    #[test]
    fn the_configuration_offers_bot_then_uas() -> TestResult {
        let (bus, mut class, _other, mut device) = new_device();
        let config = control(
            &bus,
            &mut device,
            &mut class,
            setup(0x80, 6, 0x0200, 0, 255),
        )
        .ok_or("GET_DESCRIPTOR refused")?;

        let iface = u8::from(class.bot.interface);
        let (data_in, data_out) = class.data_pipe_addresses();
        let status = class.uas.status_ep.address();
        let cmd = class.uas.cmd_ep.address();
        let ep = |a: EndpointAddress| (0x05, vec![u8::from(a)]);
        let pipe = |id: u8| (0x24, vec![id]);
        assert_eq!(
            summary(&config)[1..],
            [
                (0x0B, vec![iface, 1, 0x08, 0x06, 0x50]),
                (0x04, vec![iface, 0, 2, 0x08, 0x06, 0x50]),
                ep(data_in),
                ep(data_out),
                (0x04, vec![iface, 1, 4, 0x08, 0x06, 0x62]),
                ep(data_in),
                pipe(3),
                ep(data_out),
                pipe(4),
                ep(status),
                pipe(2),
                ep(cmd),
                pipe(1),
            ],
            "BOT on alt 0, UAS on alt 1 with its pipe usage descriptors"
        );
        Ok(())
    }

    #[test]
    fn bot_class_requests_are_answered_on_alternate_setting_0_only() -> TestResult {
        let (bus, mut class, _other, mut device) = new_device();
        let iface = u16::from(u8::from(class.bot.interface));
        let get_max_lun = setup(0xA1, 0xFE, 0, iface, 1);
        let reset = setup(0x21, 0xFF, 0, iface, 0);

        assert_eq!(
            control(&bus, &mut device, &mut class, get_max_lun),
            Some(vec![0]),
            "GET MAX LUN on alt 0"
        );

        let (_, bot_out) = class.data_pipe_addresses();
        host_sends(&bus, bot_out, cbw());
        class.poll();
        assert!(
            class.bot.transport.get_command().is_some(),
            "a command is pending"
        );
        assert_eq!(
            control(&bus, &mut device, &mut class, reset),
            Some(vec![]),
            "Mass Storage Reset accepted on alt 0"
        );
        assert!(
            class.bot.transport.get_command().is_none(),
            "the reset dropped the pending command"
        );

        class.set_alt_setting(class.bot.interface, 1);
        assert_eq!(
            control(&bus, &mut device, &mut class, get_max_lun),
            None,
            "no GET MAX LUN on alt 1"
        );
        assert_eq!(
            control(&bus, &mut device, &mut class, reset),
            None,
            "no Mass Storage Reset on alt 1"
        );
        Ok(())
    }

    #[test]
    fn bot_class_requests_for_another_interface_are_left_alone() -> TestResult {
        let (bus, mut class, other, mut device) = new_device();
        let theirs = u16::from(u8::from(other));

        assert_eq!(
            control(
                &bus,
                &mut device,
                &mut class,
                setup(0xA1, 0xFE, 0, theirs, 1)
            ),
            None,
            "GET MAX LUN for another interface should be refused"
        );

        let (_, bot_out) = class.data_pipe_addresses();
        host_sends(&bus, bot_out, cbw());
        class.poll();
        assert_eq!(
            control(
                &bus,
                &mut device,
                &mut class,
                setup(0x21, 0xFF, 0, theirs, 0)
            ),
            None,
            "a Mass Storage Reset for another interface should be refused"
        );
        assert!(
            class.bot.transport.get_command().is_some(),
            "a Mass Storage Reset for another interface should leave the command in flight"
        );
        Ok(())
    }

    #[test]
    fn zero_copy_reaches_the_bot_transport() -> TestResult {
        let (bus, mut class) = new_class();
        class.enable_zero_copy();
        let (_, bot_out) = class.data_pipe_addresses();

        let mut out_cbw = cbw();
        out_cbw[8..12].copy_from_slice(&64u32.to_le_bytes()); // 64 bytes, host to device
        host_sends(&bus, bot_out, out_cbw);
        host_sends(&bus, bot_out, vec![0x5A; 64]);
        for _ in 0..8 {
            class.poll();
        }

        assert_eq!(
            bus.0.lock().unwrap().out[&u8::from(bot_out)].len(),
            1,
            "the OUT data was left for the subclass"
        );
        Ok(())
    }
}
