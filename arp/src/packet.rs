use std::fmt;
use std::net::Ipv4Addr;

pub const REQUEST: u16 = 1;
pub const REPLY: u16 = 2;
pub const SIZE: usize = 28;

const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const ZERO: Mac = Mac([0; 6]);

    pub fn from_ip(ip: Ipv4Addr) -> Mac {
        let [a, b, c, d] = ip.octets();
        Mac([0x02, 0x00, a, b, c, d])
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[derive(Clone, Copy)]
pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4Addr,
    pub target_mac: Mac,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn request(sender_mac: Mac, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        ArpPacket {
            op: REQUEST,
            sender_mac,
            sender_ip,
            target_mac: Mac::ZERO,
            target_ip,
        }
    }

    pub fn reply_to(&self, mac: Mac) -> Self {
        ArpPacket {
            op: REPLY,
            sender_mac: mac,
            sender_ip: self.target_ip,
            target_mac: self.sender_mac,
            target_ip: self.sender_ip,
        }
    }

    pub fn encode(&self) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        b[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        b[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
        b[4] = 6;
        b[5] = 4;
        b[6..8].copy_from_slice(&self.op.to_be_bytes());
        b[8..14].copy_from_slice(&self.sender_mac.0);
        b[14..18].copy_from_slice(&self.sender_ip.octets());
        b[18..24].copy_from_slice(&self.target_mac.0);
        b[24..28].copy_from_slice(&self.target_ip.octets());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < SIZE
            || u16::from_be_bytes([b[0], b[1]]) != HTYPE_ETHERNET
            || u16::from_be_bytes([b[2], b[3]]) != PTYPE_IPV4
            || b[4] != 6
            || b[5] != 4
        {
            return None;
        }

        let mac = |i: usize| Mac([b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5]]);
        let ip = |i: usize| Ipv4Addr::new(b[i], b[i + 1], b[i + 2], b[i + 3]);

        Some(ArpPacket {
            op: u16::from_be_bytes([b[6], b[7]]),
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }
}

impl fmt::Display for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.op {
            REQUEST => write!(
                f,
                "ARP Request: who has {}? tell {} ({})",
                self.target_ip, self.sender_ip, self.sender_mac
            ),
            REPLY => write!(f, "ARP Reply: {} is at {}", self.sender_ip, self.sender_mac),
            op => write!(f, "ARP op {op}"),
        }
    }
}
