use crate::network_checksum;

#[repr(u8)]
enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    RedirectMessage = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    BadIpHeader = 12,
}

#[repr(C, packed)]
struct IcmpHeader {
    type_: u8,
    code: u8,
    checksum: u16,
    field: u32,
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
}
