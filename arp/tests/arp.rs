//! Black-box tests: start the real `arp` binary and talk to it with
//! hand-built RFC 826 packets over UDP.

use std::io::Write;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_arp");

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start_server() -> Server {
    for _ in 0..5 {
        let port = free_port();
        let mut child = Command::new(BIN)
            .args(["server", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Give the server a brief moment; if it exited (port race), retry.
        let mut failed = false;
        let probe_addr = ("127.0.0.1", port);
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.connect(probe_addr).unwrap();
        probe.set_read_timeout(Some(Duration::from_millis(80))).unwrap();
        for _ in 0..25 {
            if let Ok(Some(_)) = child.try_wait() {
                failed = true;
                break;
            }
            let _ = probe.send(&packet(1, [2, 0, 9, 9, 9, 9], [9, 9, 9, 9], [0; 6], [192, 168, 1, 1]));
            if recv(&probe).is_some() {
                return Server { child, port };
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        if !failed {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    panic!("server did not start");
}

fn socket(server: &Server, timeout: Duration) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(("127.0.0.1", server.port)).unwrap();
    s.set_read_timeout(Some(timeout)).unwrap();
    s
}

/// RFC 826 packet for Ethernet (htype 1) and IPv4 (ptype 0x0800).
fn packet(op: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0x00, 0x01, 0x08, 0x00, 6, 4];
    b.extend_from_slice(&op.to_be_bytes());
    b.extend_from_slice(&sha);
    b.extend_from_slice(&spa);
    b.extend_from_slice(&tha);
    b.extend_from_slice(&tpa);
    b
}

fn recv(s: &UdpSocket) -> Option<Vec<u8>> {
    let mut buf = [0u8; 128];
    s.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
}

fn ask(s: &UdpSocket, me_mac: [u8; 6], me_ip: [u8; 4], who: [u8; 4]) -> Option<Vec<u8>> {
    s.send(&packet(1, me_mac, me_ip, [0; 6], who)).unwrap();
    recv(s)
}

const ME_MAC: [u8; 6] = [0x02, 0x00, 192, 168, 1, 100];
const ME_IP: [u8; 4] = [192, 168, 1, 100];

#[test]
fn reply_has_rfc826_layout() {
    let server = start_server();
    let s = socket(&server, Duration::from_secs(1));
    let reply = ask(&s, ME_MAC, ME_IP, [192, 168, 1, 10]).expect("reply");
    let expected = packet(2, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x0a], [192, 168, 1, 10], ME_MAC, ME_IP);
    assert_eq!(reply.len(), 28);
    assert_eq!(reply, expected);
}

#[test]
fn all_preloaded_hosts_resolve() {
    let server = start_server();
    let s = socket(&server, Duration::from_secs(1));
    for (last, mac_last) in [(1u8, 0x01u8), (10, 0x0a), (20, 0x14), (30, 0x1e)] {
        let reply = ask(&s, ME_MAC, ME_IP, [192, 168, 1, last]).unwrap();
        assert_eq!(&reply[8..14], &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, mac_last]);
    }
}

#[test]
fn unknown_host_gets_no_reply() {
    let server = start_server();
    let s = socket(&server, Duration::from_millis(300));
    assert!(ask(&s, ME_MAC, ME_IP, [192, 168, 1, 99]).is_none());
}

#[test]
fn server_learns_the_sender() {
    let server = start_server();
    let a = socket(&server, Duration::from_secs(1));
    let b = socket(&server, Duration::from_secs(1));
    let a_mac = [0x02, 0x00, 10, 0, 0, 5];
    let before = socket(&server, Duration::from_millis(300));
    assert!(ask(&before, ME_MAC, ME_IP, [10, 0, 0, 5]).is_none(), "not known yet");
    ask(&a, a_mac, [10, 0, 0, 5], [192, 168, 1, 1]).unwrap();
    let reply = ask(&b, ME_MAC, ME_IP, [10, 0, 0, 5]).expect("learned");
    assert_eq!(&reply[8..14], &a_mac);
}

#[test]
fn malformed_packets_are_ignored() {
    let server = start_server();
    let s = socket(&server, Duration::from_millis(300));
    let mut wrong_htype = packet(1, ME_MAC, ME_IP, [0; 6], [192, 168, 1, 1]);
    wrong_htype[1] = 6;
    let mut wrong_ptype = packet(1, ME_MAC, ME_IP, [0; 6], [192, 168, 1, 1]);
    wrong_ptype[2] = 0x86;
    let mut wrong_len = packet(1, ME_MAC, ME_IP, [0; 6], [192, 168, 1, 1]);
    wrong_len[4] = 8;
    let reply_op = packet(2, ME_MAC, ME_IP, [0; 6], [192, 168, 1, 1]);
    let short = packet(1, ME_MAC, ME_IP, [0; 6], [192, 168, 1, 1])[..20].to_vec();
    let mut overlong = packet(1, ME_MAC, ME_IP, [0; 6], [192, 168, 1, 1]);
    overlong.push(0xff);
    for bad in [wrong_htype, wrong_ptype, wrong_len, reply_op, short, overlong, vec![]] {
        s.send(&bad).unwrap();
        assert!(recv(&s).is_none(), "answered {bad:?}");
    }
    assert!(ask(&s, ME_MAC, ME_IP, [192, 168, 1, 1]).is_some(), "still alive");
}

#[test]
fn static_entry_cannot_be_spoofed() {
    let server = start_server();
    let attacker = socket(&server, Duration::from_secs(1));
    let victim = socket(&server, Duration::from_secs(1));
    let fake = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    ask(&attacker, fake, [192, 168, 1, 1], [192, 168, 1, 10]).unwrap();
    let reply = ask(&victim, ME_MAC, ME_IP, [192, 168, 1, 1]).unwrap();
    assert_eq!(
        &reply[8..14],
        &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x01],
        "static gateway entry must remain protected"
    );
}

#[test]
fn invalid_sender_is_not_learned() {
    let server = start_server();
    let s = socket(&server, Duration::from_millis(300));
    // Unspecified sender IP (0.0.0.0) and zero MAC must not enter the ARP table.
    ask(&s, ME_MAC, [0, 0, 0, 0], [192, 168, 1, 1]).unwrap();
    assert!(ask(&s, ME_MAC, ME_IP, [0, 0, 0, 0]).is_none());

    ask(&s, [0; 6], [10, 0, 0, 99], [192, 168, 1, 1]).unwrap();
    assert!(ask(&s, ME_MAC, ME_IP, [10, 0, 0, 99]).is_none());
}

fn run_client(server: &Server, my_ip: &str, input: &str) -> String {
    let mut child = Command::new(BIN)
        .args(["client", my_ip, "127.0.0.1", &server.port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn client_uses_its_cache() {
    let server = start_server();
    let out = run_client(&server, "192.168.1.100", "192.168.1.10\n192.168.1.10\ncache\nquit\n");
    assert!(out.contains("02:00:c0:a8:01:64"), "MAC derived from IP");
    assert_eq!(out.matches("Sent: ARP Request").count(), 1);
    assert!(out.contains("Received: ARP Reply: 192.168.1.10 is at 00:1a:2b:3c:4d:0a"));
    assert!(out.contains("Cache hit: 192.168.1.10 is at 00:1a:2b:3c:4d:0a"));
    assert!(out.contains("192.168.1.10     00:1a:2b:3c:4d:0a  "));
}

#[test]
fn second_client_finds_the_first() {
    let server = start_server();
    run_client(&server, "192.168.1.100", "192.168.1.1\nquit\n");
    let out = run_client(&server, "192.168.1.101", "192.168.1.100\nnot-an-ip\nquit\n");
    assert!(out.contains("192.168.1.100 is at 02:00:c0:a8:01:64"), "{out}");
    assert!(out.contains("Invalid IPv4 address: not-an-ip"));
}

#[test]
fn client_self_lookup_flush_and_retries() {
    let server = start_server();
    let out = run_client(
        &server,
        "192.168.1.100",
        "192.168.1.100\n192.168.1.10\nflush\n192.168.1.10\n192.168.1.99\nquit\n",
    );
    assert!(out.contains("Self: 192.168.1.100 is at 02:00:c0:a8:01:64"), "{out}");
    assert!(out.contains("ARP cache flushed"), "{out}");
    // Two network requests for 192.168.1.10 (one before flush, one after), plus one for .99
    assert_eq!(out.matches("Sent: ARP Request").count(), 3, "{out}");
    assert!(out.contains("Retry (2/3): ARP Request: who has 192.168.1.99?"), "{out}");
    assert!(out.contains("Retry (3/3): ARP Request: who has 192.168.1.99?"), "{out}");
    assert!(out.contains("No reply for 192.168.1.99"), "{out}");
}

#[test]
fn udp_round_trip_time() {
    let server = start_server();
    let s = socket(&server, Duration::from_secs(1));
    let rounds = 1000;
    let start = Instant::now();
    for _ in 0..rounds {
        ask(&s, ME_MAC, ME_IP, [192, 168, 1, 10]).unwrap();
    }
    let per_request = start.elapsed() / rounds;
    println!("UDP request/reply round trip: {:.1} us", per_request.as_secs_f64() * 1e6);

    let start = Instant::now();
    let unanswered = socket(&server, Duration::from_millis(500));
    assert!(ask(&unanswered, ME_MAC, ME_IP, [192, 168, 1, 99]).is_none());
    println!("unknown host costs the full timeout: {:.0} ms", start.elapsed().as_secs_f64() * 1e3);
}
