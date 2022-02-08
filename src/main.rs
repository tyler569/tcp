use std::fs::File;
use std::io::{Error, Read, Result, Write};
use std::os::unix::io::FromRawFd;
use ifstructs::ifreq;
use libc::{open, close, ioctl, c_ulong, c_short, c_void, O_RDWR};

mod icmp;
mod ip;
mod packet;

fn main() -> Result<()> {
    let mut buffer = [0u8; 1500];
    let mut file = unsafe { tun_alloc("tun0") }?;

    let n_read = file.read(&mut buffer)?;
    println!("read: {} {:02x?}", n_read, &buffer[..n_read]);

    let n_written = file.write(&buffer[..n_read])?;
    println!("written: {}", n_written);
    Ok(())
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

pub unsafe fn network_checksum(pointer: *const u16, length: usize, checksum: u16) -> u16 {
    let mut acc = !checksum.swap_bytes();
    unsafe {
        for i in 0..length/2 {
            acc = ones_complement_sum(acc,
                    (*pointer.offset(i as isize)).swap_bytes());
        }
    }
    !acc
}
