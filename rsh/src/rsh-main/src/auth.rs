use std::fs;

use rsh_crypto::keyfile::parse_public;
use rsh_crypto::PublicKey;

use crate::paths;

pub fn auth_data(session_key: &[u8], user: &str) -> Vec<u8> {
    let mut data = b"rsh-auth".to_vec();
    data.extend_from_slice(session_key);
    data.extend_from_slice(user.as_bytes());
    data
}

pub fn is_authorized(key: &PublicKey) -> bool {
    let text = fs::read_to_string(paths::authorized_keys()).unwrap_or_default();
    text.lines()
        .filter_map(|line| parse_public(line).ok())
        .any(|(known, _)| known == *key)
}
