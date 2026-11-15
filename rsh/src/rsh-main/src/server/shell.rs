use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use super::echo::EchoFilter;
use crate::codec::invalid;
use crate::message::Message;
use crate::transport::{Sender, Transport};

type Shared<T> = Arc<Mutex<T>>;

pub fn run(mut t: Transport, cwd: &Path, peer: &str) -> io::Result<()> {
    let mut child = match spawn(cwd) {
        Ok(child) => child,
        Err(e) => {
            t.send(&Message::Failure(format!("cannot start shell: {e}")))?;
            return Ok(());
        }
    };
    t.send(&Message::Success("shell started".to_string()))?;
    println!("[{peer}] shell started (pid {})", child.id());

    let (sender, mut receiver) = t.split();
    let sender = Arc::new(Mutex::new(sender));
    let echo = Arc::new(Mutex::new(EchoFilter::new()));

    let mut stdin = child.stdin.take();
    let stdout = child.stdout.take().map(|s| pump(s, sender.clone(), Some(echo.clone())));
    let stderr = child.stderr.take().map(|s| pump(s, sender.clone(), None));
    let child = Arc::new(Mutex::new(child));
    watch_exit(child.clone(), sender, [stdout, stderr], peer.to_string());

    let result = loop {
        match receiver.recv() {
            Ok(Message::Data(data)) => {
                if let Some(input) = stdin.as_mut() {
                    echo.lock().unwrap().expect(&data);
                    if input.write_all(&data).and_then(|_| input.flush()).is_err() {
                        stdin = None;
                    }
                }
            }
            Ok(Message::Eof) => stdin = None,
            Ok(Message::Disconnect) => break Ok(()),
            Ok(_) => break Err(invalid("unexpected message during shell")),
            Err(e) => break Err(e),
        }
    };

    drop(stdin);
    let _ = child.lock().unwrap().kill();
    result
}

fn pump(
    mut source: impl Read + Send + 'static,
    sender: Shared<Sender>,
    echo: Option<Shared<EchoFilter>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = match source.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let data = match &echo {
                Some(filter) => filter.lock().unwrap().filter(&buf[..n]),
                None => buf[..n].to_vec(),
            };
            if !data.is_empty() && sender.lock().unwrap().send(&Message::Data(data)).is_err() {
                return;
            }
        }
        if let Some(filter) = &echo {
            let rest = filter.lock().unwrap().flush();
            if !rest.is_empty() {
                let _ = sender.lock().unwrap().send(&Message::Data(rest));
            }
        }
    })
}

fn watch_exit(
    child: Shared<Child>,
    sender: Shared<Sender>,
    pumps: [Option<JoinHandle<()>>; 2],
    peer: String,
) {
    thread::spawn(move || {
        for pump in pumps.into_iter().flatten() {
            let _ = pump.join();
        }
        let code = child
            .lock()
            .unwrap()
            .wait()
            .ok()
            .and_then(|status| status.code())
            .unwrap_or(-1);
        println!("[{peer}] shell exited with code {code}");
        let _ = sender.lock().unwrap().send(&Message::Exit(code));
    });
}

fn spawn(cwd: &Path) -> io::Result<Child> {
    shell_command()
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

#[cfg(windows)]
fn shell_command() -> Command {
    Command::new("cmd.exe")
}

#[cfg(not(windows))]
fn shell_command() -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-i");
    cmd
}
