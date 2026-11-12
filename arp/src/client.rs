use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use crate::cache::Cache;
use crate::packet::{ArpPacket, Mac, REPLY};

struct Client {
    socket: UdpSocket,
    cache: Cache,
    ip: Ipv4Addr,
    mac: Mac,
}

pub fn run(ip: Ipv4Addr, server: &str, port: u16) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect((server, port))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut client = Client {
        socket,
        cache: Cache::new(),
        ip,
        mac: Mac::from_ip(ip),
    };

    println!("ARP client {} ({}) using server {server}:{port}", client.ip, client.mac);
    println!("Enter an IPv4 address to resolve, 'cache' to show the cache, or 'quit'");

    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            return Ok(());
        }

        match line.trim() {
            "" => {}
            "quit" | "exit" => return Ok(()),
            "cache" => client.cache.print(),
            input => match input.parse::<Ipv4Addr>() {
                Ok(target) => client.resolve(target)?,
                Err(_) => println!("Invalid IPv4 address: {input}"),
            },
        }
    }
}

impl Client {
    fn resolve(&mut self, target: Ipv4Addr) -> io::Result<()> {
        if let Some(mac) = self.cache.get(target) {
            println!("Cache hit: {target} is at {mac}");
            return Ok(());
        }

        let request = ArpPacket::request(self.mac, self.ip, target);
        self.socket.send(&request.encode())?;
        println!("Sent: {request}");

        let mut buf = [0u8; 64];
        loop {
            let n = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(_) => {
                    println!("No reply for {target}");
                    return Ok(());
                }
            };
            if let Some(reply) = ArpPacket::decode(&buf[..n]) {
                if reply.op == REPLY && reply.sender_ip == target {
                    println!("Received: {reply}");
                    self.cache.insert(target, reply.sender_mac);
                    return Ok(());
                }
            }
        }
    }
}
