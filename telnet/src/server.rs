use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::commands;
use crate::protocol::{escape, Parser};

pub fn run(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("Telnet server listening on port {port}");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Accept failed: {e}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        println!("Client connected: {peer}");

        thread::spawn(move || {
            if let Err(e) = handle(stream) {
                eprintln!("Client {peer} error: {e}");
            }
            println!("Client disconnected: {peer}");
        });
    }

    Ok(())
}

fn send(stream: &mut TcpStream, text: &str) -> io::Result<()> {
    stream.write_all(&escape(text.replace('\n', "\r\n").as_bytes()))
}

fn handle(mut stream: TcpStream) -> io::Result<()> {
    let mut parser = Parser::new();
    let mut buf = [0u8; 1024];
    let mut line = Vec::new();

    send(&mut stream, "Welcome to the Rust telnet server\nType 'help' for commands\n> ")?;

    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }

        let (data, replies) = parser.feed(&buf[..n]);
        if !replies.is_empty() {
            stream.write_all(&replies)?;
        }

        for b in data {
            match b {
                b'\n' => {
                    let input = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    match commands::execute(&input) {
                        Some(reply) if reply.is_empty() => send(&mut stream, "> ")?,
                        Some(reply) => send(&mut stream, &format!("{reply}\n> "))?,
                        None => {
                            send(&mut stream, "Goodbye\n")?;
                            return Ok(());
                        }
                    }
                }
                8 | 127 => {
                    line.pop();
                }
                b'\r' | 0 => {}
                _ => line.push(b),
            }
        }
    }
}
