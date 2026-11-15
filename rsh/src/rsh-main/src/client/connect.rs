use std::io;
use std::net::TcpStream;

use rsh_crypto::keyfile;

use crate::handshake;
use crate::paths;
use crate::transport::Transport;

pub fn open(host: &str, port: u16) -> io::Result<Transport> {
    let path = paths::identity();
    let identity = keyfile::load_private(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "cannot load identity {}: {e} (run rsh-keygen first)",
                path.display()
            ),
        )
    })?;
    let stream = TcpStream::connect((host, port))?;
    handshake::client(stream, &format!("{host}:{port}"), &identity, &paths::user_name())
}
