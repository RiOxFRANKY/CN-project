use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use crate::cache::Cache;
use crate::packet::{ArpPacket, Mac, REPLY};

const MAX_RETRIES: usize = 3;
const RETRY_TIMEOUT: Duration = Duration::from_millis(600);

struct Client {
    socket: UdpSocket,
    cache: Cache,
    ip: Ipv4Addr,
    mac: Mac,
}

pub fn run(ip: Ipv4Addr, server: &str, port: u16) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect((server, port))?;
    socket.set_read_timeout(Some(RETRY_TIMEOUT))?;

    let mut client = Client {
        socket,
        cache: Cache::new(),
        ip,
        mac: Mac::from_ip(ip),
    };

    println!("ARP client {} ({}) using server {server}:{port}", client.ip, client.mac);
    println!("Enter an IPv4 address to resolve, 'cache', 'flush', or 'quit'");

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
            "flush" => {
                client.cache.clear();
                println!("ARP cache flushed");
            }
            input => match input.parse::<Ipv4Addr>() {
                Ok(target) => client.resolve(target)?,
                Err(_) => println!("Invalid IPv4 address: {input}"),
            },
        }
    }
}

impl Client {
    fn resolve(&mut self, target: Ipv4Addr) -> io::Result<()> {
        if target == self.ip {
            println!("Self: {} is at {}", self.ip, self.mac);
            return Ok(());
        }

        if let Some(mac) = self.cache.get(target) {
            println!("Cache hit: {target} is at {mac}");
            return Ok(());
        }

        let request = ArpPacket::request(self.mac, self.ip, target);
        let encoded = request.encode();
        let mut buf = [0u8; 64];

        for attempt in 1..=MAX_RETRIES {
            self.socket.send(&encoded)?;
            if attempt == 1 {
                println!("Sent: {request}");
            } else {
                println!("Retry ({attempt}/{MAX_RETRIES}): {request}");
            }

            let deadline = Instant::now() + RETRY_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                self.socket.set_read_timeout(Some(remaining))?;
                let n = match self.socket.recv(&mut buf) {
                    Ok(n) => n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(e) => return Err(e),
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

        println!("No reply for {target}");
        Ok(())
    }
}
