mod echo;
mod files;
mod session;
mod shell;

use std::io;
use std::net::TcpListener;
use std::thread;

use rsh_crypto::{keyfile, KeyPair, PrivateKey, Rng};

use crate::paths;

pub fn run(port: u16) -> io::Result<()> {
    let host_key = load_host_key()?;
    println!("Host key fingerprint: {}", host_key.public().fingerprint());
    println!("Authorized keys file: {}", paths::authorized_keys().display());

    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("rsh server listening on port {port}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || session::handle(stream, host_key));
            }
            Err(e) => eprintln!("accept failed: {e}"),
        }
    }
    Ok(())
}

fn load_host_key() -> io::Result<PrivateKey> {
    let path = paths::host_key();
    if path.exists() {
        return keyfile::load_private(&path);
    }
    let pair = KeyPair::generate(&mut Rng::new());
    keyfile::save_pair(&path, &pair, "host")?;
    println!("Generated new host key at {}", path.display());
    Ok(pair.private)
}
