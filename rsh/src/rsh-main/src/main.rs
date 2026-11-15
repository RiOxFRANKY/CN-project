use std::env;
use std::process;

use rsh_main::{client, server, DEFAULT_PORT};

fn main() {
    let args: Vec<String> = env::args().collect();

    let result = match args.get(1).map(String::as_str) {
        Some("server") => server::run(port(args.get(2))).map(|_| 0),
        Some("connect") => match args.get(2) {
            Some(host) => client::run(host, port(args.get(3))),
            None => usage(),
        },
        _ => usage(),
    };

    match result {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("rsh: {e}");
            process::exit(1);
        }
    }
}

fn port(arg: Option<&String>) -> u16 {
    match arg {
        None => DEFAULT_PORT,
        Some(p) => p.parse().unwrap_or_else(|_| usage()),
    }
}

fn usage() -> ! {
    eprintln!("Usage:\n  rsh server [port]\n  rsh connect <host> [port]");
    process::exit(1);
}
