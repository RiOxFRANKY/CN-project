use std::io;
use std::net::TcpStream;

use rsh_crypto::StreamCipher;

use crate::message::Message;
use crate::packet::{read_frame, write_frame};

const CLIENT_TO_SERVER: &[u8] = b"rsh client to server";
const SERVER_TO_CLIENT: &[u8] = b"rsh server to client";

pub enum Role {
    Client,
    Server,
}

pub struct Sender {
    stream: TcpStream,
    cipher: Option<StreamCipher>,
}

pub struct Receiver {
    stream: TcpStream,
    cipher: Option<StreamCipher>,
}

pub struct Transport {
    sender: Sender,
    receiver: Receiver,
}

impl Sender {
    pub fn send(&mut self, message: &Message) -> io::Result<()> {
        let mut data = message.encode();
        if let Some(cipher) = &mut self.cipher {
            cipher.apply(&mut data);
        }
        write_frame(&mut self.stream, &data)
    }
}

impl Receiver {
    pub fn recv(&mut self) -> io::Result<Message> {
        let mut data = read_frame(&mut self.stream)?;
        if let Some(cipher) = &mut self.cipher {
            cipher.apply(&mut data);
        }
        Message::decode(&data)
    }
}

impl Transport {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        Ok(Transport {
            sender: Sender {
                stream: stream.try_clone()?,
                cipher: None,
            },
            receiver: Receiver {
                stream,
                cipher: None,
            },
        })
    }

    pub fn encrypt_with(&mut self, key: &[u8], role: Role) {
        let c2s = StreamCipher::new(key, CLIENT_TO_SERVER);
        let s2c = StreamCipher::new(key, SERVER_TO_CLIENT);
        let (outgoing, incoming) = match role {
            Role::Client => (c2s, s2c),
            Role::Server => (s2c, c2s),
        };
        self.sender.cipher = Some(outgoing);
        self.receiver.cipher = Some(incoming);
    }

    pub fn send(&mut self, message: &Message) -> io::Result<()> {
        self.sender.send(message)
    }

    pub fn recv(&mut self) -> io::Result<Message> {
        self.receiver.recv()
    }

    pub fn split(self) -> (Sender, Receiver) {
        (self.sender, self.receiver)
    }
}
