use crate::network_checksum;

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct IpHeader {
    version_ihl: u8,
    dscp_ecn: u8,
    total_len: u16,
    id: u16,
    flags_frag_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: u32,
    destination: u32,
}

/// Swap all the multibyte fields in an [`IpHeader`], providing convenient
/// native-endian access to everything super fast. When this goes out of
/// scope, swap them all back.
///
/// In the future, it should be impossible to do some things to headers in
/// this wrapper, for example it should be impossible to compute or set
/// their checksums, as that will always be wrong in native-endian order.
///
/// This currently DOES NOT actually swap to native-endian order, it assumes
/// the running machine is Little-Endian for now. Rust doesn't have a
/// convenient builtin API for "swap_bytes from X endian to native" without
/// going through `[u8; N]` objects.
struct NeIpHeader<'a>(&'a mut IpHeader);

impl<'a> Drop for NeIpHeader<'a> {
    fn drop(&mut self) {
        self.0.bswap_internal();
    }
}

impl IpHeader {
    pub fn version(&self) -> u8 {
        (self.version_ihl & 0xF0) >> 4
    }

    pub fn header_len(&self) -> u8 {
        (self.version_ihl & 0x0F) * 4
    }

    fn bswap_internal(&mut self) {
        self.total_len = self.total_len.swap_bytes();
        self.id = self.id.swap_bytes();
        self.flags_frag_offset = self.flags_frag_offset.swap_bytes();
        self.checksum = self.checksum.swap_bytes();
        self.source = self.source.swap_bytes();
        self.destination = self.destination.swap_bytes();
    }

    fn bswap(&mut self) -> NeIpHeader {
        self.bswap_internal();
        NeIpHeader(self)
    }

    pub fn checksum(&self) -> u16 {
        // SAFETY: network_checksum is unsafe becuase it cannot verify the
        // valid length of the pointer. Here, we pass a pointer to an
        // IpHeader and its known size of `header_len()`, thus it is safe.
        unsafe {
            network_checksum(
                self as *const IpHeader as *const u16,
                self.header_len() as usize,
                self.checksum
            )
        }
    }

    fn set_checksum(&mut self) {
        self.checksum = self.checksum();
    }
}

#[test]
fn test_ip_checksum() {
    let buffer: &mut [u8] = &mut [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    ];
    let header = unsafe { &mut *(buffer.as_mut_ptr() as *mut IpHeader) };
    assert_eq!(header.checksum(), 0xb861);
}

#[test]
fn test_bswap() {
    let buffer: &mut [u8] = &mut [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    ];
    let header = unsafe { &mut *(buffer.as_mut_ptr() as *mut IpHeader) };
    {
        let ne_header = header.bswap();
        assert_eq!(ne_header.0.total_len, 0x0073);
    }
    assert_eq!(header.total_len, 0x7300);
}
