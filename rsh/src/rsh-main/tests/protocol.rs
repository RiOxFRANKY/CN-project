//! Wire format and handshake tests. Every handshake runs over a real TCP
//! connection on 127.0.0.1, through a relay that records the bytes on the wire.
//! `cargo test --test protocol -- --nocapture` prints the frame sizes.

use std::env;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};

use rsh_crypto::keyfile::public_line;
use rsh_crypto::{KeyPair, PrivateKey, PublicKey, Rng};
use rsh_main::handshake;
use rsh_main::message::Message;
use rsh_main::packet::{read_frame, write_frame};
use rsh_main::transport::Transport;

static SETUP: Once = Once::new();
static TRUSTED: Mutex<Option<KeyPair>> = Mutex::new(None);

/// One RSH_HOME for the whole test binary, with one trusted client key.
fn trusted_client() -> PrivateKey {
    SETUP.call_once(|| {
        let dir = env::temp_dir().join(format!("rsh-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        env::set_var("RSH_HOME", &dir);
        let pair = KeyPair::generate(&mut Rng::new());
        fs::write(dir.join("authorized_keys"), public_line(&pair.public, "test") + "\n").unwrap();
        *TRUSTED.lock().unwrap() = Some(pair);
    });
    TRUSTED.lock().unwrap().unwrap().private
}

fn rsh_home() -> PathBuf {
    PathBuf::from(env::var_os("RSH_HOME").unwrap())
}

type ServerResult = io::Result<(Transport, String)>;

fn start_server(host_key: PrivateKey) -> (u16, JoinHandle<ServerResult>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept()?;
        handshake::server(stream, &host_key)
    });
    (port, handle)
}

#[derive(Default)]
struct Capture {
    to_server: Vec<u8>,
    to_client: Vec<u8>,
}

/// A TCP relay between client and server that keeps a copy of every byte.
fn start_relay(server_port: u16) -> (u16, Arc<Mutex<Capture>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let capture = Arc::new(Mutex::new(Capture::default()));
    let cap = capture.clone();
    thread::spawn(move || {
        let (client, _) = listener.accept().unwrap();
        let server = TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let copy = |mut from: TcpStream, mut to: TcpStream, cap: Arc<Mutex<Capture>>, up: bool| {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = from.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let mut c = cap.lock().unwrap();
                    let side = if up { &mut c.to_server } else { &mut c.to_client };
                    side.extend_from_slice(&buf[..n]);
                    drop(c);
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = to.shutdown(Shutdown::Write);
            })
        };
        let a = copy(client.try_clone().unwrap(), server.try_clone().unwrap(), cap.clone(), true);
        let b = copy(server, client, cap, false);
        let _ = a.join();
        let _ = b.join();
    });
    (port, capture)
}

fn frames(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        out.push(read_frame(&mut bytes).unwrap());
    }
    out
}

fn connect(port: u16, host: &str, identity: &PrivateKey) -> io::Result<Transport> {
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    handshake::client(stream, host, identity, "student")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn wait_for_bytes(capture: &Arc<Mutex<Capture>>, up: usize, down: usize) {
    for _ in 0..200 {
        {
            let c = capture.lock().unwrap();
            if c.to_server.len() >= up && c.to_client.len() >= down {
                return;
            }
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn every_message_round_trips() {
    let key = PublicKey { n: 0xa9cd_b4f4_c93a_988f, e: 65537 };
    let messages = vec![
        Message::HostKey(key),
        Message::SessionKey(vec![1, 2, 3]),
        Message::Auth { user: "student".into(), key, signature: 42 },
        Message::Success("welcome".into()),
        Message::Failure("denied".into()),
        Message::Shell,
        Message::Data(b"dir\r\n".to_vec()),
        Message::Eof,
        Message::Exit(-7),
        Message::Upload { path: "docs/".into(), name: "a.txt".into(), data: vec![0; 300] },
        Message::Download("a.txt".into()),
        Message::File { name: "a.txt".into(), data: vec![9; 10] },
        Message::Disconnect,
    ];
    for m in messages {
        let decoded = Message::decode(&m.encode()).unwrap();
        assert_eq!(format!("{decoded:?}"), format!("{m:?}"));
    }
}

#[test]
fn malformed_messages_are_rejected() {
    assert!(Message::decode(&[]).is_err());
    assert!(Message::decode(&[99]).is_err());
    let data = Message::Data(b"hello".to_vec()).encode();
    assert!(Message::decode(&data[..data.len() - 1]).is_err());
    let mut longer = data.clone();
    longer.push(0);
    assert!(Message::decode(&longer).is_err());
    let bad_utf8 = [4u8, 0, 0, 0, 2, 0xff, 0xfe];
    assert!(Message::decode(&bad_utf8).is_err());
}

#[test]
fn frames_round_trip_and_enforce_limits() {
    let mut wire = Vec::new();
    write_frame(&mut wire, b"first").unwrap();
    write_frame(&mut wire, &[7u8; 1000]).unwrap();
    assert_eq!(wire.len(), 4 + 5 + 4 + 1000);
    let mut r = Cursor::new(wire);
    assert_eq!(read_frame(&mut r).unwrap(), b"first");
    assert_eq!(read_frame(&mut r).unwrap(), vec![7u8; 1000]);
    assert!(read_frame(&mut r).is_err());

    assert!(read_frame(&mut Cursor::new([0u8, 0, 0, 0])).is_err());
    let too_big = (64u32 * 1024 * 1024 + 1).to_be_bytes();
    assert!(read_frame(&mut Cursor::new(too_big)).is_err());
    assert!(write_frame(&mut Vec::new(), &vec![0u8; 64 * 1024 * 1024 + 1]).is_err());
}

#[test]
fn handshake_then_encrypted_data() {
    let identity = trusted_client();
    let host_key = KeyPair::generate(&mut Rng::new()).private;
    let (server_port, server) = start_server(host_key);
    let (relay_port, capture) = start_relay(server_port);

    let mut client = connect(relay_port, "handshake-test", &identity).unwrap();
    let (mut server_t, user) = server.join().unwrap().unwrap();
    assert_eq!(user, "student");

    let secret = b"echo secret-command\n".to_vec();
    client.send(&Message::Data(secret.clone())).unwrap();
    match server_t.recv().unwrap() {
        Message::Data(d) => assert_eq!(d, secret),
        other => panic!("got {other:?}"),
    }
    let answer = b"secret-command\n".to_vec();
    server_t.send(&Message::Data(answer.clone())).unwrap();
    match client.recv().unwrap() {
        Message::Data(d) => assert_eq!(d, answer),
        other => panic!("got {other:?}"),
    }

    wait_for_bytes(&capture, 122, 69);
    let c = capture.lock().unwrap();
    assert!(!contains(&c.to_server, b"secret-command"));
    assert!(!contains(&c.to_client, b"secret-command"));
    assert!(!contains(&c.to_server, b"student"), "user name is encrypted too");

    let up = frames(&c.to_server);
    let down = frames(&c.to_client);
    println!("client -> server frames: {:?}", up.iter().map(|f| f.len() + 4).collect::<Vec<_>>());
    println!("server -> client frames: {:?}", down.iter().map(|f| f.len() + 4).collect::<Vec<_>>());
    println!("handshake bytes: up {} down {}", c.to_server.len() - (up[2].len() + 4), c.to_client.len() - (down[2].len() + 4));
    // HostKey and SessionKey travel in clear; the host key is readable.
    assert_eq!(down[0][0], 1);
    assert_eq!(up[0][0], 2);
}

#[test]
fn unknown_client_key_is_rejected() {
    trusted_client();
    let stranger = KeyPair::generate(&mut Rng::new()).private;
    let (port, server) = start_server(KeyPair::generate(&mut Rng::new()).private);
    let err = connect(port, "reject-test", &stranger).err().expect("must fail");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("not in authorized_keys"), "{err}");
    assert!(server.join().unwrap().is_err());
}

#[test]
fn changed_host_key_is_refused() {
    let identity = trusted_client();
    let (port, server) = start_server(KeyPair::generate(&mut Rng::new()).private);
    connect(port, "changing-host", &identity).unwrap();
    server.join().unwrap().unwrap();
    let known = fs::read_to_string(rsh_home().join("known_hosts")).unwrap();
    assert!(known.lines().any(|l| l.starts_with("changing-host rsh-rsa ")));

    // Same name, new host key: a man in the middle, or a reinstalled server.
    let (port, server) = start_server(KeyPair::generate(&mut Rng::new()).private);
    let err = connect(port, "changing-host", &identity).err().expect("must fail");
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("HAS CHANGED"), "{err}");
    drop(server);
}

#[test]
fn recorded_login_can_be_replayed() {
    let identity = trusted_client();
    let host_key = KeyPair::generate(&mut Rng::new()).private;

    let (server_port, server) = start_server(host_key);
    let (relay_port, capture) = start_relay(server_port);
    let client = connect(relay_port, "replay-test", &identity).unwrap();
    server.join().unwrap().unwrap();
    wait_for_bytes(&capture, 1, 1);
    drop(client);
    let recorded = capture.lock().unwrap().to_server.clone();
    let login = frames(&recorded);
    assert_eq!(login.len(), 2, "SessionKey and Auth");

    // An eavesdropper sends the same two frames again, without any key.
    let (port, server) = start_server(host_key);
    let mut attacker = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _host_key_frame = read_frame(&mut attacker).unwrap();
    for frame in &login {
        write_frame(&mut attacker, frame).unwrap();
    }
    let (_, user) = server.join().unwrap().expect("server accepts the replay");
    assert_eq!(user, "student");
}
