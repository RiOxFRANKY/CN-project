use std::env;
use std::io;
use std::net::TcpStream;
use std::path::PathBuf;

use rsh_crypto::PrivateKey;

use super::{files, shell};
use crate::codec::invalid;
use crate::handshake;
use crate::message::Message;

pub fn handle(stream: TcpStream, host_key: PrivateKey) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    println!("[{peer}] connected");
    match serve(stream, &host_key, &peer) {
        Ok(()) => println!("[{peer}] disconnected"),
        Err(e) => println!("[{peer}] closed: {e}"),
    }
}

fn serve(stream: TcpStream, host_key: &PrivateKey, peer: &str) -> io::Result<()> {
    let (mut t, user) = handshake::server(stream, host_key)?;
    println!("[{peer}] authenticated as {user}");
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    loop {
        match t.recv()? {
            Message::Shell => return shell::run(t, &cwd, peer),
            Message::Upload { path, name, data } => {
                let reply = match files::upload(&cwd, &path, &name, &data) {
                    Ok(text) => Message::Success(text),
                    Err(e) => Message::Failure(e.to_string()),
                };
                println!("[{peer}] upload {name} -> {path}: {reply:?}");
                t.send(&reply)?;
            }
            Message::Download(path) => {
                let reply = match files::download(&cwd, &path) {
                    Ok((name, data)) => Message::File { name, data },
                    Err(e) => Message::Failure(e.to_string()),
                };
                println!("[{peer}] download {path}");
                t.send(&reply)?;
            }
            Message::Disconnect => return Ok(()),
            _ => return Err(invalid("unexpected message")),
        }
    }
}
