mod args;
mod report;
mod transfer;

use std::env;
use std::process;

use args::Location;

fn main() {
    let raw: Vec<String> = env::args().skip(1).collect();
    let options = args::parse(&raw).unwrap_or_else(|e| {
        eprintln!("{e}\n{}", args::USAGE);
        process::exit(1);
    });

    let result = match (&options.source, &options.target) {
        (Location::Local(local), Location::Remote { host, path }) => {
            transfer::upload(host, options.port, local, path)
        }
        (Location::Remote { host, path }, Location::Local(local)) => {
            transfer::download(host, options.port, path, local)
        }
        _ => {
            eprintln!("rcp: exactly one of source and target must be host:path\n{}", args::USAGE);
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("rcp: {e}");
        process::exit(1);
    }
}
