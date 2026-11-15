use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::rsa::{KeyPair, PrivateKey, PublicKey};

const PUBLIC_TAG: &str = "rsh-rsa";
const PRIVATE_TAG: &str = "rsh-rsa-private";

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn hex(field: Option<&str>) -> io::Result<u64> {
    let field = field.ok_or_else(|| invalid("missing key field"))?;
    u64::from_str_radix(field, 16).map_err(|_| invalid("bad key field"))
}

pub fn public_line(key: &PublicKey, comment: &str) -> String {
    format!("{PUBLIC_TAG} {:016x} {:x} {comment}", key.n, key.e)
}

pub fn parse_public(line: &str) -> io::Result<(PublicKey, String)> {
    let mut parts = line.split_whitespace();
    if parts.next() != Some(PUBLIC_TAG) {
        return Err(invalid("not an rsh public key"));
    }
    let n = hex(parts.next())?;
    let e = hex(parts.next())?;
    let comment = parts.collect::<Vec<_>>().join(" ");
    Ok((PublicKey { n, e }, comment))
}

pub fn private_text(key: &PrivateKey) -> String {
    format!("{PRIVATE_TAG} {:016x} {:x} {:016x}\n", key.n, key.e, key.d)
}

pub fn parse_private(text: &str) -> io::Result<PrivateKey> {
    let mut parts = text.split_whitespace();
    if parts.next() != Some(PRIVATE_TAG) {
        return Err(invalid("not an rsh private key"));
    }
    let n = hex(parts.next())?;
    let e = hex(parts.next())?;
    let d = hex(parts.next())?;
    Ok(PrivateKey { n, e, d })
}

pub fn public_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

pub fn save_pair(path: &Path, pair: &KeyPair, comment: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    fs::write(path, private_text(&pair.private))?;
    fs::write(public_path(path), public_line(&pair.public, comment) + "\n")
}

pub fn load_private(path: &Path) -> io::Result<PrivateKey> {
    parse_private(&fs::read_to_string(path)?)
}

pub fn load_public(path: &Path) -> io::Result<(PublicKey, String)> {
    parse_public(fs::read_to_string(path)?.trim())
}
