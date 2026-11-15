use std::env;
use std::path::PathBuf;

pub fn home() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn rsh_dir() -> PathBuf {
    match env::var_os("RSH_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home().join(".rsh"),
    }
}

pub fn identity() -> PathBuf {
    rsh_dir().join("id_rsh")
}

pub fn host_key() -> PathBuf {
    rsh_dir().join("host_key")
}

pub fn authorized_keys() -> PathBuf {
    rsh_dir().join("authorized_keys")
}

pub fn known_hosts() -> PathBuf {
    rsh_dir().join("known_hosts")
}

pub fn user_name() -> String {
    env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

pub fn host_name() -> String {
    env::var("HOSTNAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}
