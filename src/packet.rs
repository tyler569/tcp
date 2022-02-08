use crate::ip::IpHeader;

struct Packet<'a> {
    l3_offset: Option<isize>,
    l4_offset: Option<isize>,
    data_offset: Option<isize>,
    data: &'a mut [u8],
}

impl<'a> Packet<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        Packet {
            data,
            l3_offset: None,
            l4_offset: None,
            data_offset: None,
        }
    }

    fn l3_ptr(&mut self) -> Option<*mut u8> {
        unsafe { Some(self.data.as_mut_ptr().offset(self.l3_offset?)) }
    }

    fn l4_ptr(&mut self) -> Option<*mut u8> {
        unsafe { Some(self.data.as_mut_ptr().offset(self.l4_offset?)) }
    }

    fn data_ptr(&mut self) -> Option<*mut u8> {
        unsafe { Some(self.data.as_mut_ptr().offset(self.data_offset?)) }
    }

    pub fn ip_header(&mut self) -> Option<&mut IpHeader> {
        unsafe { Some(&mut *(self.l3_ptr()? as *mut IpHeader)) }
    }
}

#[test]
fn test_packet_sub() {
    let buffer = &mut [0; 32];
    buffer[0] = 0x45;
    let mut packet = Packet::new(buffer);
    packet.l3_offset = Some(0);
    let header = packet.ip_header().unwrap();
    assert_eq!(header.checksum(), !0x4500u16);
    assert!(packet.data_ptr().is_none());
}
