use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

use rsh_main::client;
use rsh_main::message::Message;

use crate::report;

fn unexpected() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unexpected reply from server")
}

pub fn upload(host: &str, port: u16, local: &Path, remote: &str) -> io::Result<()> {
    let data = fs::read(local).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", local.display())))?;
    let name = local
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no file name"))?;

    let start = Instant::now();
    let mut t = client::open(host, port)?;
    t.send(&Message::Upload {
        path: remote.to_string(),
        name: name.clone(),
        data: data.clone(),
    })?;
    let reply = t.recv()?;
    t.send(&Message::Disconnect)?;

    match reply {
        Message::Success(_) => {
            report::done(&name, data.len(), start);
            Ok(())
        }
        Message::Failure(reason) => Err(io::Error::other(reason)),
        _ => Err(unexpected()),
    }
}

pub fn download(host: &str, port: u16, remote: &str, local: &Path) -> io::Result<()> {
    let start = Instant::now();
    let mut t = client::open(host, port)?;
    t.send(&Message::Download(remote.to_string()))?;
    let reply = t.recv()?;
    t.send(&Message::Disconnect)?;

    match reply {
        Message::File { name, data } => {
            let target = if local.is_dir() {
                local.join(&name)
            } else {
                local.to_path_buf()
            };
            fs::write(&target, &data)?;
            report::done(&name, data.len(), start);
            Ok(())
        }
        Message::Failure(reason) => Err(io::Error::other(reason)),
        _ => Err(unexpected()),
    }
}
