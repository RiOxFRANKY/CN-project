use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

use super::connect::open;
use crate::codec::invalid;
use crate::message::Message;
use crate::transport::Sender;

pub fn run(host: &str, port: u16) -> io::Result<i32> {
    let mut t = open(host, port)?;
    t.send(&Message::Shell)?;
    match t.recv()? {
        Message::Success(_) => {}
        Message::Failure(reason) => return Err(io::Error::other(reason)),
        _ => return Err(invalid("expected shell reply")),
    }
    eprintln!("Connected to {host}:{port}. Type 'exit' to leave.");

    let (sender, mut receiver) = t.split();
    let sender = Arc::new(Mutex::new(sender));
    forward_stdin(sender.clone());

    let mut stdout = io::stdout();
    let code = loop {
        match receiver.recv()? {
            Message::Data(data) => {
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            Message::Exit(code) => break code,
            _ => return Err(invalid("unexpected message during shell")),
        }
    };

    let _ = sender.lock().unwrap().send(&Message::Disconnect);
    eprintln!("Connection to {host} closed.");
    Ok(code)
}

fn forward_stdin(sender: Arc<Mutex<Sender>>) {
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            let n = match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let message = Message::Data(buf[..n].to_vec());
            if sender.lock().unwrap().send(&message).is_err() {
                return;
            }
        }
        let _ = sender.lock().unwrap().send(&Message::Eof);
    });
}
