mod client;
mod commands;
mod protocol;
mod server;

use std::env;
use std::process;

const DEFAULT_PORT: u16 = 2323;

fn main() {
    let args: Vec<String> = env::args().collect();

    let result = match args.get(1).map(String::as_str) {
        Some("server") => server::run(port(args.get(2))),
        Some("client") => {
            let host = args.get(2).map(String::as_str).unwrap_or("127.0.0.1");
            client::run(host, port(args.get(3)))
        }
        _ => {
            eprintln!("Usage:\n  telnet server [port]\n  telnet client [host] [port]");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn port(arg: Option<&String>) -> u16 {
    arg.and_then(|p| p.parse().ok()).unwrap_or(DEFAULT_PORT)
}
