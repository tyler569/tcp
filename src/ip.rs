use crate::{network_checksum, AsSlice};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct IpProtocol(u8);

impl IpProtocol {
    pub const ICMP: Self = Self(1);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
}

impl std::fmt::Debug for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ICMP => write!(f, "IpProtocol(ICMP)"),
            Self::TCP => write!(f, "IpProtocol(TCP)"),
            Self::UDP => write!(f, "IpProtocol(UDP)"),
            _ => write!(f, "IpProtocol(Unknown ({}))", self.0),
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct IpHeader {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags_frag_offset: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub source: u32,
    pub destination: u32,
}

impl IpHeader {
    pub const RESERVED_BIT: u16 = 0x8000;
    pub const DF_BIT: u16 = 0x4000;
    pub const MF_BIT: u16 = 0x2000;

    pub fn version(&self) -> u8 {
        ((self.version_ihl & 0xF0) >> 4) & 0x7
    }

    pub fn header_len(&self) -> u8 {
        (self.version_ihl & 0x0F) * 4
    }

    pub fn reserved_bit(&self) -> bool {
        assert!(self.is_native_endian());
        self.flags_frag_offset & Self::RESERVED_BIT != 0
    }

    pub fn df_bit(&self) -> bool {
        assert!(self.is_native_endian());
        self.flags_frag_offset & Self::DF_BIT != 0
    }

    pub fn mf_bit(&self) -> bool {
        assert!(self.is_native_endian());
        self.flags_frag_offset & Self::MF_BIT != 0
    }

    pub fn frag_offset(&self) -> usize {
        assert!(self.is_native_endian());
        (self.flags_frag_offset & 0x1FFF) as usize * 8
    }

    pub fn bswap(&mut self) {
        self.total_len = self.total_len.swap_bytes();
        self.id = self.id.swap_bytes();
        self.flags_frag_offset = self.flags_frag_offset.swap_bytes();
        self.checksum = self.checksum.swap_bytes();
        self.source = self.source.swap_bytes();
        self.destination = self.destination.swap_bytes();

        // marker bit in MSB of version_ihl
        self.version_ihl ^= 0x80;
    }

    pub fn is_native_endian(&self) -> bool {
        self.version_ihl & 0x80 != 0
    }

    pub fn checksum(&self) -> u16 {
        assert!(!self.is_native_endian());
        // SAFETY: network_checksum is unsafe becuase it cannot verify the
        // valid length of the pointer. Here, we pass a pointer to an
        // IpHeader and its known size of `header_len()`, thus it is safe.
        unsafe {
            network_checksum(
                self as *const IpHeader as *const u16,
                self.header_len() as usize,
                self.checksum,
            )
        }
    }

    pub fn set_checksum(&mut self) {
        self.checksum = self.checksum();
    }

    pub fn reply_header(&self) -> Self {
        Self {
            version_ihl: 0x45 | (self.version_ihl & 0x80),
            dscp_ecn: self.dscp_ecn,
            total_len: 0,
            id: self.id,
            flags_frag_offset: self.flags_frag_offset,
            ttl: self.ttl - 1,
            protocol: self.protocol,
            checksum: 0,
            source: self.destination,
            destination: self.source,
        }
    }
}

impl AsSlice for IpHeader {}

#[test]
fn test_ip_checksum() {
    let buffer: &mut [u8] = &mut [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61,
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    let header = unsafe { &mut *(buffer.as_mut_ptr() as *mut IpHeader) };
    assert_eq!(header.checksum(), 0x61b8);
}

#[test]
fn test_bswap() {
    let buffer: &mut [u8] = &mut [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61,
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    let header = unsafe { &mut *(buffer.as_mut_ptr() as *mut IpHeader) };
    header.bswap();
    assert_eq!(header.total_len, 0x0073);
    header.bswap();
    assert_eq!(header.total_len, 0x7300);
}
