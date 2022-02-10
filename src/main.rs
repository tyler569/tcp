use ifstructs::ifreq;
use libc::{c_short, c_ulong, c_void, close, ioctl, open, O_RDWR};
use std::fs::File;
use std::io::{Error, Read, Result, Write};
use std::os::unix::io::FromRawFd;

mod icmp;
mod ip;
mod packet;

use icmp::{IcmpHeader, IcmpType};
use ip::IpProtocol;
use packet::Packet;

static mut INTERFACE: Option<Box<File>> = None;

fn main() -> Result<()> {
    let file = unsafe { tun_alloc("tun0") }?;

    unsafe {
        INTERFACE = Some(Box::new(file));
    }

    loop {
        let mut packet = read_packet();

        if packet.data[0] & 0xF0 != 0x40 {
            println!("Not IPv4, discarding");
            continue;
        }

        if let Some(ip_header) = packet.ip_header_mut() {
            ip_header.bswap();
        }

        handle_ip(&mut packet);
    }
}

fn read_packet() -> Packet {
    let mut buffer = [0; 4096];
    let n_read =
        unsafe { INTERFACE.as_mut().unwrap().read(&mut buffer) }.unwrap();
    let vec = buffer[..n_read].to_vec();
    println!("-> {:02x?}", vec);
    Packet::new(vec)
}

fn send_packet(packet: &Packet) {
    println!("<- {:02x?}", packet.whole());
    unsafe {
        INTERFACE
            .as_mut()
            .unwrap()
            .write(packet.whole().unwrap())
            .unwrap();
    }
}

fn handle_ip(packet: &mut Packet) {
    let (protocol, len) = {
        let ip = packet.ip_header().unwrap();
        (ip.protocol, ip.header_len())
    };
    packet.l4_offset = Some(len as isize);
    match protocol {
        IpProtocol::ICMP => handle_icmp(packet),
        _ => {}
    };
}

fn handle_icmp(packet: &mut Packet) {
    let icmp_type = packet.icmp_header().unwrap().type_;
    match icmp_type {
        icmp::IcmpType::ECHO_REQUEST => handle_icmp_echo(packet),
        _ => {}
    };
}

fn handle_icmp_echo(packet: &mut Packet) {
    packet.data_offset = packet.l4_offset.map(|x| x + 4);

    send_icmp(packet, IcmpType::ECHO_REPLY, packet.data().unwrap());
}

fn send_icmp(packet: &Packet, type_: icmp::IcmpType, data: &[u8]) {
    let reply_header = packet.ip_header().unwrap().reply_header();
    let icmp_header = IcmpHeader {
        type_,
        code: 0,
        checksum: 0,
    };
    let data_len = data.len();
    let mut reply_packet = Packet::new_from_data(data);
    reply_packet.fill_l4(icmp_header);
    reply_packet.fill_l3(reply_header);
    reply_packet.ip_header_mut().unwrap().total_len =
        reply_packet.len().unwrap() as u16;
    reply_packet.ip_header_mut().unwrap().bswap();
    reply_packet.ip_header_mut().unwrap().set_checksum();
    unsafe {
        reply_packet
            .icmp_header_mut()
            .unwrap()
            .set_checksum(data_len + 4);
    }

    send_packet(&reply_packet);
}

// tun: 1 tap: 2 no_pi: 4096
const IFF_TUN: c_short = 1;
// const IFF_TAP: c_short = 2;
const IFF_NO_PI: c_short = 4096;
const TUNSETIFF: c_ulong = 1074025674;

unsafe fn tun_alloc(name: &str) -> Result<File> {
    let fd = open("/dev/net/tun\0".as_ptr() as *const i8, O_RDWR);
    if fd < 0 {
        return Err(Error::from_raw_os_error(-fd));
    }

    let mut ifreq = ifreq::from_name(name).unwrap();
    ifreq.set_flags(IFF_TUN | IFF_NO_PI);

    let err = ioctl(fd, TUNSETIFF, &ifreq as *const ifreq as *const c_void);
    if err < 0 {
        close(fd);
        return Err(Error::from_raw_os_error(-err));
    }
    Ok(File::from_raw_fd(fd))
}

fn ones_complement_sum(a: u16, b: u16) -> u16 {
    let (mut result, overflow) = a.overflowing_add(b);
    if overflow {
        result += 1;
    }
    result
}

pub unsafe fn network_checksum(
    pointer: *const u16,
    length: usize,
    checksum: u16,
) -> u16 {
    let mut acc = !checksum.swap_bytes();
    for i in 0..length / 2 {
        acc = ones_complement_sum(
            acc,
            (*pointer.offset(i as isize)).swap_bytes(),
        );
    }
    (!acc).swap_bytes()
}

trait AsSlice {
    fn as_slice<'a>(&'a self) -> &[u8]
    where
        Self: Sized,
    {
        unsafe {
            std::slice::from_raw_parts::<'a, u8>(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}
