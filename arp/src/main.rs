mod cache;
mod client;
mod packet;
mod server;

use std::env;
use std::net::Ipv4Addr;
use std::process;

const DEFAULT_PORT: u16 = 4000;

fn main() {
    let args: Vec<String> = env::args().collect();

    let result = match args.get(1).map(String::as_str) {
        Some("server") => server::run(port(args.get(2))),
        Some("client") => {
            let ip = match args.get(2).map(|s| s.parse::<Ipv4Addr>()) {
                None => Ipv4Addr::new(192, 168, 1, 100),
                Some(Ok(ip)) => ip,
                Some(Err(_)) => usage(),
            };
            let server = args.get(3).map(String::as_str).unwrap_or("127.0.0.1");
            client::run(ip, server, port(args.get(4)))
        }
        _ => usage(),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn port(arg: Option<&String>) -> u16 {
    arg.and_then(|p| p.parse().ok()).unwrap_or(DEFAULT_PORT)
}

fn usage() -> ! {
    eprintln!("Usage:\n  arp server [port]\n  arp client [my-ip] [server] [port]");
    process::exit(1);
}
