use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};

use crate::packet::{ArpPacket, Mac, REQUEST};

fn initial_table() -> BTreeMap<Ipv4Addr, Mac> {
    BTreeMap::from([
        (Ipv4Addr::new(192, 168, 1, 1), Mac([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x01])),
        (Ipv4Addr::new(192, 168, 1, 10), Mac([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x0a])),
        (Ipv4Addr::new(192, 168, 1, 20), Mac([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x14])),
        (Ipv4Addr::new(192, 168, 1, 30), Mac([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x1e])),
    ])
}

pub fn run(port: u16) -> io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    let mut table = initial_table();

    println!("ARP server listening on UDP port {port}");
    for (ip, mac) in &table {
        println!("  {ip:<15}  {mac}");
    }

    let mut buf = [0u8; 64];
    loop {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let request = match ArpPacket::decode(&buf[..n]) {
            Some(p) if p.op == REQUEST => p,
            _ => continue,
        };
        println!("{from} -> {request}");

        if table.insert(request.sender_ip, request.sender_mac).is_none() {
            println!("Learned {} is at {}", request.sender_ip, request.sender_mac);
        }

        match table.get(&request.target_ip) {
            Some(&mac) => {
                let reply = request.reply_to(mac);
                if let Err(e) = socket.send_to(&reply.encode(), from) {
                    eprintln!("Send to {from} failed: {e}");
                }
                println!("{from} <- {reply}");
            }
            None => println!("No host has {}, request dropped", request.target_ip),
        }
    }
}
