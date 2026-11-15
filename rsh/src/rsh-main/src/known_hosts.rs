use std::fs::{self, OpenOptions};
use std::io::{self, Write};

use rsh_crypto::keyfile::{parse_public, public_line};
use rsh_crypto::PublicKey;

use crate::paths;

pub fn verify(host: &str, key: &PublicKey) -> io::Result<()> {
    let path = paths::known_hosts();
    let text = fs::read_to_string(&path).unwrap_or_default();

    for line in text.lines() {
        let Some((name, rest)) = line.split_once(' ') else {
            continue;
        };
        if name != host {
            continue;
        }
        if let Ok((known, _)) = parse_public(rest) {
            if known == *key {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "HOST KEY FOR {host} HAS CHANGED (now {}). Remove its line from {} if this is expected.",
                    key.fingerprint(),
                    path.display()
                ),
            ));
        }
    }

    eprintln!("Host '{host}' is not known. Key fingerprint is {}.", key.fingerprint());
    fs::create_dir_all(paths::rsh_dir())?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{host} {}", public_line(key, "").trim_end())?;
    eprintln!("Warning: Permanently added '{host}' to the list of known hosts.");
    Ok(())
}
