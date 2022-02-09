use crate::AsSlice;
use crate::ip::IpHeader;
use crate::icmp::IcmpHeader;

pub struct PacketView<'a> {
    pub l3_offset: isize,
    pub l4_offset: isize,
    pub data_offset: isize,
    pub data: &'a [u8],
}

pub struct Packet {
    pub l3_offset: Option<isize>,
    pub l4_offset: Option<isize>,
    pub data_offset: Option<isize>,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(data: Vec<u8>) -> Self {
        Packet {
            data,
            l3_offset: Some(0),
            l4_offset: None,
            data_offset: None,
        }
    }

    const WITH_DATA_OFFSET: isize = 128;

    pub fn new_from_data(data: &[u8]) -> Self {
        let mut vec = vec![0u8; data.len() + Self::WITH_DATA_OFFSET as usize];
        vec[Self::WITH_DATA_OFFSET as usize..].copy_from_slice(data);
        Self {
            l3_offset: None,
            l4_offset: None,
            data_offset: Some(Self::WITH_DATA_OFFSET),
            data: vec,
        }
    }

    pub fn fill_l4<T: AsSlice>(&mut self, l4: T) {
        let s = l4.as_slice();
        let l = s.len();
        let d = self.data_offset.unwrap() as usize;
        self.data[d - l..d].copy_from_slice(s);
        self.l4_offset = Some((d - l) as isize);
    }

    pub fn fill_l3<T: AsSlice>(&mut self, l3: T) {
        let s = l3.as_slice();
        let l = s.len();
        let d = self.l4_offset.unwrap() as usize;
        self.data[d - l..d].copy_from_slice(s);
        self.l3_offset = Some((d - l) as isize);
    }

    fn l3_ptr(&self) -> Option<*const u8> {
        unsafe { Some(self.data.as_ptr().offset(self.l3_offset?)) }
    }

    fn l4_ptr(&self) -> Option<*const u8> {
        unsafe { Some(self.data.as_ptr().offset(self.l4_offset?)) }
    }

    fn l3_mut_ptr(&mut self) -> Option<*mut u8> {
        unsafe { Some(self.data.as_mut_ptr().offset(self.l3_offset?)) }
    }

    fn l4_mut_ptr(&mut self) -> Option<*mut u8> {
        unsafe { Some(self.data.as_mut_ptr().offset(self.l4_offset?)) }
    }

    pub fn ip_header(&self) -> Option<&IpHeader> {
        unsafe { Some(&*(self.l3_ptr()? as *const IpHeader)) }
    }

    pub fn icmp_header(&self) -> Option<&IcmpHeader> {
        unsafe { Some(&*(self.l4_ptr()? as *const IcmpHeader)) }
    }

    pub fn ip_header_mut(&mut self) -> Option<&mut IpHeader> {
        unsafe { Some(&mut *(self.l3_mut_ptr()? as *mut IpHeader)) }
    }

    pub fn icmp_header_mut(&mut self) -> Option<&mut IcmpHeader> {
        unsafe { Some(&mut *(self.l4_mut_ptr()? as *mut IcmpHeader)) }
    }

    pub fn data(&self) -> Option<&[u8]> {
        Some(&self.data[self.data_offset? as usize..])
    }

    pub fn data_mut(&mut self) -> Option<&mut [u8]> {
        Some(&mut self.data[self.data_offset? as usize..])
    }

    pub fn whole(&self) -> Option<&[u8]> {
        Some(&self.data[self.l3_offset? as usize..])
    }

    pub fn len(&self) -> Option<usize> {
        Some(self.data.len() - self.l3_offset? as usize)
    }
}

#[test]
fn test_packet_sub() {
    let buffer = &mut [0; 32];
    buffer[0] = 0x45;
    let mut packet = Packet::new(buffer.to_vec());
    packet.l3_offset = Some(0);
    let header = packet.ip_header().unwrap();
    assert_eq!(header.checksum(), !0x4500u16);
    assert!(packet.data().is_none());
}
