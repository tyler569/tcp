use crate::{AsSlice, network_checksum};

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IcmpType(u8);

impl IcmpType {
    pub const ECHO_REPLY: Self = Self(0);
    pub const DESTINATION_UNREACHABLE: Self = Self(3);
    pub const SOURCE_QUENCH: Self = Self(4);
    pub const REDIRECT_MESSAGE: Self = Self(5);
    pub const ECHO_REQUEST: Self = Self(8);
    pub const ROUTER_ADVERTISEMENT: Self = Self(9);
    pub const ROUTER_SOLICITATION: Self = Self(10);
    pub const TIME_EXCEEDED: Self = Self(11);
    pub const BAD_IP_HEADER: Self = Self(12);
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct IcmpHeader {
    pub type_: IcmpType,
    pub code: u8,
    pub checksum: u16,
}

impl IcmpHeader {
    // SAFETY: Needs to be given a valid length
    pub unsafe fn checksum(&self, length: usize) -> u16 {
        network_checksum(
            self as *const IcmpHeader as *const u16,
            length,
            self.checksum
        )
    }

    // SAFETY: Needs to be given a valid length
    pub unsafe fn set_checksum(&mut self, length: usize) {
        self.checksum = self.checksum(length);
    }
}

impl AsSlice for IcmpHeader {}
