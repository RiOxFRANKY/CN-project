use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process;
use std::thread;

use crate::protocol::{escape, Parser};

pub fn run(host: &str, port: u16) -> io::Result<()> {
    let mut writer = TcpStream::connect((host, port))?;
    println!("Connected to {host}:{port}");

    let mut reader = writer.try_clone()?;
    let mut replier = writer.try_clone()?;

    let receiver = thread::spawn(move || {
        let mut parser = Parser::new();
        let mut buf = [0u8; 1024];
        let mut stdout = io::stdout();

        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let (data, replies) = parser.feed(&buf[..n]);
            if !replies.is_empty() && replier.write_all(&replies).is_err() {
                break;
            }
            let _ = stdout.write_all(&data);
            let _ = stdout.flush();
        }

        println!("\nConnection closed");
        process::exit(0);
    });

    for line in io::stdin().lock().lines() {
        let mut bytes = escape(line?.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        writer.write_all(&bytes)?;
    }

    writer.shutdown(Shutdown::Write)?;
    let _ = receiver.join();
    Ok(())
}
