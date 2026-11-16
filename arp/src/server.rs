use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};

use crate::packet::{ArpPacket, Mac, REQUEST};

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Static,
    Dynamic,
}

#[derive(Clone, Copy)]
struct Entry {
    mac: Mac,
    kind: EntryKind,
}

fn static_entry(mac: [u8; 6]) -> Entry {
    Entry {
        mac: Mac(mac),
        kind: EntryKind::Static,
    }
}

fn initial_table() -> BTreeMap<Ipv4Addr, Entry> {
    BTreeMap::from([
        (Ipv4Addr::new(192, 168, 1, 1), static_entry([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x01])),
        (Ipv4Addr::new(192, 168, 1, 10), static_entry([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x0a])),
        (Ipv4Addr::new(192, 168, 1, 20), static_entry([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x14])),
        (Ipv4Addr::new(192, 168, 1, 30), static_entry([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x1e])),
    ])
}

pub fn run(port: u16) -> io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    let mut table = initial_table();

    println!("ARP server listening on UDP port {port}");
    for (ip, entry) in &table {
        println!("  {ip:<15}  {}  [static]", entry.mac);
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

        if request.sender_ip.is_unspecified() || !request.sender_mac.is_valid_unicast() {
            eprintln!(
                "Ignored invalid sender {} ({})",
                request.sender_ip, request.sender_mac
            );
        } else {
            learn(&mut table, request.sender_ip, request.sender_mac);
        }

        match table.get(&request.target_ip) {
            Some(entry) => {
                let reply = request.reply_to(entry.mac);
                match socket.send_to(&reply.encode(), from) {
                    Ok(_) => println!("{from} <- {reply}"),
                    Err(e) => eprintln!("Send to {from} failed: {e}"),
                }
            }
            None => println!("No host has {}, request dropped", request.target_ip),
        }
    }
}

fn learn(table: &mut BTreeMap<Ipv4Addr, Entry>, ip: Ipv4Addr, mac: Mac) {
    match table.get_mut(&ip) {
        None => {
            table.insert(ip, Entry { mac, kind: EntryKind::Dynamic });
            println!("Learned {ip} is at {mac}");
        }
        Some(entry) if entry.mac == mac => {}
        Some(entry) if entry.kind == EntryKind::Static => {
            eprintln!(
                "WARNING: ARP spoof attempt for static IP {ip} (claimed {mac}, keeping {})",
                entry.mac
            );
        }
        Some(entry) => {
            eprintln!(
                "WARNING: MAC changed for dynamic IP {ip} ({} -> {mac})",
                entry.mac
            );
            entry.mac = mac;
        }
    }
}
