use std::fs::{self, OpenOptions};
use std::io::{self, Write};

use rsh_crypto::keyfile::{parse_public, public_line};
use rsh_crypto::PublicKey;
use rsh_main::paths;

pub fn add(key: &PublicKey, comment: &str) -> io::Result<()> {
    let path = paths::authorized_keys();
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let present = existing
        .lines()
        .filter_map(|line| parse_public(line).ok())
        .any(|(known, _)| known == *key);

    if present {
        println!("Key already in {}", path.display());
        return Ok(());
    }

    fs::create_dir_all(paths::rsh_dir())?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", public_line(key, comment))?;
    println!("Added key to {}", path.display());
    Ok(())
}
