use crate::ip::IpProtocol;
use crate::{network_checksum_2part, ones_complement_sum, AsSlice};
use std::mem::size_of;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub len: u16,
    pub checksum: u16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct UdpIpPseudoHeader {
    source_ip: u32,
    destination_ip: u32,
    zero: u8,
    protocol: IpProtocol,
    len: u16,
}

impl UdpHeader {
    pub fn reply_header(&self) -> Self {
        Self {
            source_port: self.destination_port,
            destination_port: self.source_port,
            len: self.len,
            checksum: 0,
        }
    }

    pub fn bswap(&mut self) {
        self.source_port = self.source_port.swap_bytes();
        self.destination_port = self.destination_port.swap_bytes();
        self.len = self.len.swap_bytes();
        self.checksum = self.checksum.swap_bytes();
    }

    // Safety assertions:
    // - self.len is set and correct.
    // - all fields are big-endian.
    unsafe fn ip_checksum(&self, source_ip: u32, destination_ip: u32) -> u16 {
        let pseudo_header = UdpIpPseudoHeader {
            source_ip,
            destination_ip,
            zero: 0,
            protocol: IpProtocol::UDP,
            len: self.len,
        };

        network_checksum_2part(
            self as *const UdpHeader as *const u16,
            self.len.swap_bytes().into(),
            &pseudo_header as *const UdpIpPseudoHeader as *const u16,
            size_of::<UdpIpPseudoHeader>(),
            self.checksum,
        )

        // // let checksum1 = network_partial_checksum(
        // //     &pseudo_header as *const UdpIpPseudoHeader as *const u16,
        // //     size_of::<UdpIpPseudoHeader>(),
        // // );
        // // let checksum2 = network_partial_checksum(
        // //     self as *const UdpHeader as *const u16,
        // //     self.len.swap_bytes().into(),
        // // );
        // // let a = ones_complement_sum(checksum1, checksum2);
        // // let b = ones_complement_sum(a, !self.checksum);
        // // (!b).swap_bytes()

        // // I was going to do this nicely with a real pseudo-header
        // // struct but I was having issues combining the two calls to
        // // network_checksum and decided to just try figuring it out
        // // manually.  I ended up writing this on the first try, and
        // // because of that and because the tests are now passing I'm too
        // // scared to do anything else.
        // let sc =
        //     ones_complement_sum(source_ip as u16, (source_ip >> 16) as u16);
        // let dc = ones_complement_sum(
        //     destination_ip as u16,
        //     (destination_ip >> 16) as u16,
        // );
        // let ic = ones_complement_sum(sc, dc);
        // let lc = ones_complement_sum(ic, self.len);
        // let pc = ones_complement_sum(lc, 17);

        // network_checksum(
        //     self as *const UdpHeader as *const u16,
        //     self.len.swap_bytes().into(),
        //     ones_complement_sum(self.checksum, !pc),
        // )
    }

    pub unsafe fn set_ip_checksum(
        &mut self,
        source_ip: u32,
        destination_ip: u32,
    ) {
        self.checksum = self.ip_checksum(source_ip, destination_ip);
    }
}

impl AsSlice for UdpHeader {}

#[test]
fn test_udp_checksum_1() {
    let buffer: &[u8] = &[
        0x45, 0x00, 0x00, 0x31, 0x85, 0x57, 0x40, 0x00, 0x3f, 0x11, 0xa2, 0x61,
        0x0a, 0x00, 0x00, 0x03, 0x0a, 0x00, 0x00, 0x01, 0x63, 0x9c, 0x88, 0x13,
        0x00, 0x1d, 0x91, 0x61, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x79, 0x6f, 0x75, 0x72, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x21, 0x0d,
        0x0a,
    ];

    let udp_header = unsafe { &*(buffer[20..].as_ptr() as *const UdpHeader) };
    unsafe {
        println!(
            "{:04x} {:04x}",
            0x50a2,
            udp_header.ip_checksum(0x300_000a, 0x100_000a)
        );
        assert_eq!(udp_header.ip_checksum(0x300_000a, 0x100_000a), 0x50a2);
    }
}

#[test]
fn test_udp_checksum_2() {
    let buffer: &mut [u8] = &mut [
        0x45, 0x00, 0x00, 0x1f, 0x42, 0x90, 0x40, 0x00, 0x40, 0x11, 0xe4, 0x3a,
        0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x03, 0x88, 0x13, 0x63, 0x9c,
        0x00, 0x0b, 0x8d, 0xbb, 0x68, 0x69, 0x0a,
    ];

    let mut udp_header =
        unsafe { &mut *(buffer[20..].as_mut_ptr() as *mut UdpHeader) };
    udp_header.checksum = 0;
    unsafe {
        println!(
            "{:04x} {:04x}",
            0x8dbb,
            udp_header.ip_checksum(0x100_000a, 0x300_000a)
        );
        assert_eq!(udp_header.ip_checksum(0x100_000a, 0x300_000a), 0xbb8d);
    }
}
