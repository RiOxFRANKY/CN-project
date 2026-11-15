mod args;
mod authorize;
mod output;

use std::env;
use std::io;
use std::process;

use rsh_crypto::{keyfile, KeyPair, Rng};

use args::Options;

fn main() {
    let raw: Vec<String> = env::args().skip(1).collect();
    let options = args::parse(&raw).unwrap_or_else(|e| {
        eprintln!("{e}\n{}", args::USAGE);
        process::exit(1);
    });

    if let Err(e) = run(&options) {
        eprintln!("rsh-keygen: {e}");
        process::exit(1);
    }
}

fn run(options: &Options) -> io::Result<()> {
    if options.file.exists() && !output::confirm_overwrite(&options.file)? {
        println!("Aborted.");
        return Ok(());
    }

    println!("Generating public/private rsh-rsa key pair.");
    let pair = KeyPair::generate(&mut Rng::new());
    keyfile::save_pair(&options.file, &pair, &options.comment)?;
    output::report(&options.file, &pair, &options.comment);

    if options.authorize {
        authorize::add(&pair.public, &options.comment)?;
    }
    Ok(())
}
