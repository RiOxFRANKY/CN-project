use std::io;
use std::net::TcpStream;

use rsh_crypto::{PrivateKey, Rng};

use crate::auth;
use crate::codec::invalid;
use crate::known_hosts;
use crate::message::Message;
use crate::transport::{Role, Transport};

const SESSION_KEY_LEN: usize = 32;

fn denied(reason: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

pub fn server(stream: TcpStream, host_key: &PrivateKey) -> io::Result<(Transport, String)> {
    let mut t = Transport::new(stream)?;
    t.send(&Message::HostKey(host_key.public()))?;

    let session_key = match t.recv()? {
        Message::SessionKey(encrypted) => host_key.decrypt(&encrypted)?,
        _ => return Err(invalid("expected session key")),
    };
    if session_key.len() != SESSION_KEY_LEN {
        return Err(invalid("bad session key length"));
    }
    t.encrypt_with(&session_key, Role::Server);

    let (user, key, signature) = match t.recv()? {
        Message::Auth {
            user,
            key,
            signature,
        } => (user, key, signature),
        _ => return Err(invalid("expected auth request")),
    };

    if !auth::is_authorized(&key) {
        let reason = format!("key {} is not in authorized_keys", key.fingerprint());
        t.send(&Message::Failure(reason.clone()))?;
        return Err(denied(reason));
    }
    if !key.verify(&auth::auth_data(&session_key, &user), signature) {
        let reason = "signature check failed".to_string();
        t.send(&Message::Failure(reason.clone()))?;
        return Err(denied(reason));
    }

    t.send(&Message::Success(format!("welcome {user}")))?;
    Ok((t, user))
}

pub fn client(
    stream: TcpStream,
    host: &str,
    identity: &PrivateKey,
    user: &str,
) -> io::Result<Transport> {
    let mut t = Transport::new(stream)?;

    let host_key = match t.recv()? {
        Message::HostKey(key) => key,
        _ => return Err(invalid("expected host key")),
    };
    known_hosts::verify(host, &host_key)?;

    let session_key = Rng::new().bytes(SESSION_KEY_LEN);
    t.send(&Message::SessionKey(host_key.encrypt(&session_key)))?;
    t.encrypt_with(&session_key, Role::Client);

    let signature = identity.sign(&auth::auth_data(&session_key, user));
    t.send(&Message::Auth {
        user: user.to_string(),
        key: identity.public(),
        signature,
    })?;

    match t.recv()? {
        Message::Success(_) => Ok(t),
        Message::Failure(reason) => Err(denied(format!("authentication failed: {reason}"))),
        _ => Err(invalid("expected auth result")),
    }
}
