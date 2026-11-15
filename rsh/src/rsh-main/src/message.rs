use std::io;

use rsh_crypto::PublicKey;

use crate::codec::{invalid, Reader, Writer};

const HOST_KEY: u8 = 1;
const SESSION_KEY: u8 = 2;
const AUTH: u8 = 3;
const SUCCESS: u8 = 4;
const FAILURE: u8 = 5;
const SHELL: u8 = 6;
const DATA: u8 = 7;
const EOF: u8 = 8;
const EXIT: u8 = 9;
const UPLOAD: u8 = 10;
const DOWNLOAD: u8 = 11;
const FILE: u8 = 12;
const DISCONNECT: u8 = 13;

#[derive(Debug)]
pub enum Message {
    HostKey(PublicKey),
    SessionKey(Vec<u8>),
    Auth {
        user: String,
        key: PublicKey,
        signature: u64,
    },
    Success(String),
    Failure(String),
    Shell,
    Data(Vec<u8>),
    Eof,
    Exit(i32),
    Upload {
        path: String,
        name: String,
        data: Vec<u8>,
    },
    Download(String),
    File {
        name: String,
        data: Vec<u8>,
    },
    Disconnect,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::HostKey(key) => Writer::new(HOST_KEY).u64(key.n).u64(key.e),
            Message::SessionKey(data) => Writer::new(SESSION_KEY).bytes(data),
            Message::Auth {
                user,
                key,
                signature,
            } => Writer::new(AUTH)
                .str(user)
                .u64(key.n)
                .u64(key.e)
                .u64(*signature),
            Message::Success(text) => Writer::new(SUCCESS).str(text),
            Message::Failure(text) => Writer::new(FAILURE).str(text),
            Message::Shell => Writer::new(SHELL),
            Message::Data(data) => Writer::new(DATA).bytes(data),
            Message::Eof => Writer::new(EOF),
            Message::Exit(code) => Writer::new(EXIT).u64(*code as i64 as u64),
            Message::Upload { path, name, data } => {
                Writer::new(UPLOAD).str(path).str(name).bytes(data)
            }
            Message::Download(path) => Writer::new(DOWNLOAD).str(path),
            Message::File { name, data } => Writer::new(FILE).str(name).bytes(data),
            Message::Disconnect => Writer::new(DISCONNECT),
        }
        .finish()
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut r = Reader::new(data);
        let message = match r.u8()? {
            HOST_KEY => Message::HostKey(PublicKey {
                n: r.u64()?,
                e: r.u64()?,
            }),
            SESSION_KEY => Message::SessionKey(r.bytes()?),
            AUTH => Message::Auth {
                user: r.string()?,
                key: PublicKey {
                    n: r.u64()?,
                    e: r.u64()?,
                },
                signature: r.u64()?,
            },
            SUCCESS => Message::Success(r.string()?),
            FAILURE => Message::Failure(r.string()?),
            SHELL => Message::Shell,
            DATA => Message::Data(r.bytes()?),
            EOF => Message::Eof,
            EXIT => Message::Exit(r.u64()? as i64 as i32),
            UPLOAD => Message::Upload {
                path: r.string()?,
                name: r.string()?,
                data: r.bytes()?,
            },
            DOWNLOAD => Message::Download(r.string()?),
            FILE => Message::File {
                name: r.string()?,
                data: r.bytes()?,
            },
            DISCONNECT => Message::Disconnect,
            _ => return Err(invalid("unknown message type")),
        };
        r.end()?;
        Ok(message)
    }
}
