//! A USB bus for unit tests that plays the host: it queues OUT packets and SETUP
//! packets, records what the device writes, and runs control transfers through a real
//! [`UsbDevice`], so class code that only usb-device can call (descriptors, control
//! requests, resets) is reachable from a test.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use usb_device::UsbDirection;
use usb_device::UsbError;
use usb_device::bus::{PollResult, UsbBus, UsbBusAllocator};
use usb_device::class::UsbClass;
use usb_device::class_prelude::{EndpointAddress, EndpointType};
use usb_device::device::{UsbDevice, UsbDeviceBuilder, UsbVidPid};

#[derive(Default)]
pub(crate) struct Wire {
    /// host -> device packets, by endpoint address
    pub(crate) out: HashMap<u8, VecDeque<Vec<u8>>>,
    /// device -> host packets, by endpoint address (endpoint 0 excluded)
    pub(crate) sent: HashMap<u8, Vec<Vec<u8>>>,
    /// SETUP packets the host has queued on endpoint 0
    setup: VecDeque<[u8; 8]>,
    /// what the device wrote on endpoint 0 IN
    ep0_in: Vec<u8>,
    /// a write on endpoint 0 IN waits for its completion to be reported
    ep0_in_pending: bool,
    /// the device stalled endpoint 0, i.e. refused the request
    ep0_stalled: bool,
    /// the next poll reports a bus reset
    reset: bool,
    next_index: usize,
}

/// The bus. Clones share one [`Wire`].
#[derive(Clone, Default)]
pub(crate) struct HostBus(pub(crate) Arc<Mutex<Wire>>);

impl HostBus {
    /// The host sends `packet` on the OUT endpoint `ep`.
    pub(crate) fn send(&self, ep: EndpointAddress, packet: &[u8]) {
        let mut wire = self.0.lock().unwrap();
        wire.out
            .entry(ep.into())
            .or_default()
            .push_back(packet.to_vec());
    }

    /// Everything the device wrote on the IN endpoint `ep`, concatenated, and forgotten.
    pub(crate) fn received(&self, ep: EndpointAddress) -> Vec<u8> {
        let mut wire = self.0.lock().unwrap();
        wire.sent.remove(&u8::from(ep)).unwrap_or_default().concat()
    }

    /// The next poll of the device reports a bus reset.
    pub(crate) fn reset(&self) {
        self.0.lock().unwrap().reset = true;
    }
}

impl UsbBus for HostBus {
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
        } else {
            wire.sent.entry(ep.into()).or_default().push(buf.to_vec());
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
        if wire.reset {
            wire.reset = false;
            return PollResult::Reset;
        }
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

/// A leaked allocator over a fresh bus; classes allocate from it, then [`device`] freezes it.
pub(crate) fn allocator() -> (HostBus, &'static UsbBusAllocator<HostBus>) {
    let bus = HostBus::default();
    let alloc = Box::leak(Box::new(UsbBusAllocator::new(bus.clone())));
    (bus, alloc)
}

/// The device, built once every class has allocated its endpoints.
pub(crate) fn device(alloc: &'static UsbBusAllocator<HostBus>) -> UsbDevice<'static, HostBus> {
    UsbDeviceBuilder::new(alloc, UsbVidPid(0xabcd, 0xabcd))
        .composite_with_iads()
        .build()
}

/// A SETUP packet: bmRequestType, bRequest, wValue, wIndex, wLength.
pub(crate) fn setup(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
    let mut s = [0u8; 8];
    s[0] = request_type;
    s[1] = request;
    s[2..4].copy_from_slice(&value.to_le_bytes());
    s[4..6].copy_from_slice(&index.to_le_bytes());
    s[6..8].copy_from_slice(&length.to_le_bytes());
    s
}

/// Runs one control transfer the way a host would, and returns what the device answered
/// on endpoint 0, or `None` when it refused the request.
pub(crate) fn control<C: UsbClass<HostBus>>(
    bus: &HostBus,
    device: &mut UsbDevice<'static, HostBus>,
    class: &mut C,
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

/// Splits a configuration descriptor into (bDescriptorType, the fields after it that tell
/// descriptors of that type apart).
pub(crate) fn summary(config: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = vec![];
    let mut at = 0;
    while let Some(&len) = config.get(at) {
        let d = &config[at..at + usize::from(len)];
        let keep = match d[1] {
            0x0B => 5,        // IAD: first interface, count, class, subclass, protocol
            0x04 => 6,        // interface: number, alternate, endpoints, class, subclass, protocol
            0x05 | 0x24 => 1, // endpoint address, pipe ID
            _ => 0,
        };
        out.push((d[1], d[2..2 + keep].to_vec()));
        at += usize::from(len);
    }
    out
}
