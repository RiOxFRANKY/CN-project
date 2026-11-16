# CN-project

Computer Networks protocol implementations in Rust, using only the standard library.

| Folder | Protocol | Transport | Default port |
| --- | --- | --- | --- |
| [`rsh/`](rsh) | Basic SSH: remote shell, keygen, file copy | TCP | 2222 |
| [`arp/`](arp) | ARP server and client | UDP | 4000 |

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) (stable, with Cargo)

Each folder is its own Cargo project (`rsh/` is a Cargo workspace). Run the commands below from inside that folder, and use two terminals: one for the server, one for the client.

## RSH (basic SSH)

A small SSH-style remote shell, key generator and file copy tool, split into four crates under `rsh/src/`:

| Crate | Binary | Role |
| --- | --- | --- |
| `rsh-crypto` | (library) | Toy RSA (64-bit modulus), signatures, a stream cipher for the session |
| `rsh-main` | `rsh` | Server and interactive client, plus the shared wire protocol |
| `rsh-keygen` | `rsh-keygen` | Makes key pairs, like `ssh-keygen` |
| `rcp` | `rcp` | Copies files over an rsh connection, like `scp` |

How a connection works:

1. The server sends its RSA **host key**. The client checks it against `known_hosts`: it trusts a new host the first time and refuses a key that has changed.
2. The client picks a random 32-byte **session key**, encrypts it with the host's public key and sends it. Only the server can decrypt it.
3. Both sides turn on the stream cipher, keyed by the session key, with one keystream per direction.
4. The client **authenticates** by signing the session key with its private key. The server accepts it only if the public key is in `authorized_keys`.
5. Every message after that is encrypted: the shell's input and output, or file uploads and downloads.

Keys and host files live in `~/.rsh/` (`id_rsh`, `id_rsh.pub`, `host_key`, `authorized_keys`, `known_hosts`). Set `RSH_HOME` to use another folder.

```bash
cd rsh
cargo build
cargo run --bin rsh-keygen -- -a
cargo run --bin rsh -- server [port]
cargo run --bin rsh -- connect <host> [port]
cargo run --bin rcp -- [-P port] <file> <host>:<remote-path>
cargo run --bin rcp -- [-P port] <host>:<remote-path> <local-path>
```

`rsh-keygen -a` also adds the new public key to this machine's `authorized_keys`, which is all you need when the server and client run on the same machine. For a server on another machine, append the client's `id_rsh.pub` line to the server's `authorized_keys`. Other options: `-f <file>` and `-C <comment>`.

`rsh connect` opens a real shell on the server machine: `cmd.exe` on Windows, `sh -i` elsewhere. The server starts one shell per connection and streams its input and output over the encrypted channel, so `cd`, `set`, nested shells such as `powershell`, and programs that read input all work. Typing `exit` ends the remote shell, and `rsh` exits with the shell's exit code. If the client drops, the server kills the shell. Relative paths in `rcp` are resolved against the folder the server was started in. The default port is 2222.

Limits of this basic version: there is no pseudo-terminal, so full-screen programs (editors, `more` paging) and Ctrl+C forwarding don't work. Ctrl+C ends the local client.

Example session:

```text
$ rsh connect 127.0.0.1
Host '127.0.0.1:2222' is not known. Key fingerprint is 20:05:d6:ba:20:ea:07:89.
Warning: Permanently added '127.0.0.1:2222' to the list of known hosts.
Connected to 127.0.0.1:2222. Type 'exit' to leave.
Microsoft Windows [Version 10.0.26300.9818]
(c) Microsoft Corporation. All rights reserved.

C:\work>set GREETING=hello
C:\work>echo %GREETING%
hello

C:\work>exit
Connection to 127.0.0.1 closed.

$ rcp notes.txt 127.0.0.1:
notes.txt                      100%       1532 bytes     812.4 KB/s   0.01s
```

The crypto is deliberately simple, for learning: 64-bit RSA keys can be factored in seconds, and the session has no message authentication. Do not use it to protect real systems.

### Files

- `rsh-crypto/src/math.rs`: modular multiply, power and inverse
- `rsh-crypto/src/prime.rs`: Miller-Rabin primality test and prime generation
- `rsh-crypto/src/random.rs`: random number generator
- `rsh-crypto/src/rsa.rs`: key generation, encrypt/decrypt, sign/verify, fingerprints
- `rsh-crypto/src/cipher.rs`: stream cipher for the session
- `rsh-crypto/src/hash.rs`: FNV-1a based digest
- `rsh-crypto/src/keyfile.rs`: key file format, load and save
- `rsh-main/src/packet.rs`: length-prefixed framing over TCP
- `rsh-main/src/codec.rs`, `message.rs`: message encoding
- `rsh-main/src/transport.rs`: encrypted send and receive
- `rsh-main/src/handshake.rs`: host key, session key and authentication
- `rsh-main/src/auth.rs`, `known_hosts.rs`, `paths.rs`: key checks and file locations
- `rsh-main/src/server/`: listener, per-client session, shell process streaming, echo filter for `cmd`, file transfer
- `rsh-main/src/client/`: connecting, and streaming the terminal to and from the remote shell
- `rsh-keygen/src/`: options, key output, `authorized_keys` update
- `rcp/src/`: options, upload and download, transfer report

## ARP

Sending real ARP frames needs raw Ethernet access, so this version carries real 28-byte ARP packets (RFC 826 format: Ethernet/IPv4, request and reply) over UDP instead.

- The **server** holds an IP → MAC table, answers requests for addresses it knows, and learns dynamic senders' IP and MAC from valid requests. Preloaded infrastructure entries are marked static so spoofed requests cannot overwrite them, while MAC changes on dynamic hosts emit warnings.
- The **client** has its own IP and a MAC derived from it (`02:00:` + the IP bytes). It short-circuits self-lookups, checks its **ARP cache** first, retries up to 3 times (600 ms timeout per attempt) on a miss, and caches replies for 60 seconds.

```bash
cd arp
cargo run -- server [port]
cargo run -- client [my-ip] [server] [port]
```

Client input: an IPv4 address to resolve, `cache` to show the cache, `flush` to clear the cache, or `quit`.

Hosts the server knows at startup:

| IP address | MAC address |
| --- | --- |
| 192.168.1.1 | 00:1a:2b:3c:4d:01 |
| 192.168.1.10 | 00:1a:2b:3c:4d:0a |
| 192.168.1.20 | 00:1a:2b:3c:4d:14 |
| 192.168.1.30 | 00:1a:2b:3c:4d:1e |

Example session:

```text
ARP client 192.168.1.100 (02:00:c0:a8:01:64) using server 127.0.0.1:4000
> 192.168.1.10
Sent: ARP Request: who has 192.168.1.10? tell 192.168.1.100 (02:00:c0:a8:01:64)
Received: ARP Reply: 192.168.1.10 is at 00:1a:2b:3c:4d:0a
> 192.168.1.10
Cache hit: 192.168.1.10 is at 00:1a:2b:3c:4d:0a
> 192.168.1.99
Sent: ARP Request: who has 192.168.1.99? tell 192.168.1.100 (02:00:c0:a8:01:64)
No reply for 192.168.1.99
> cache
IP address       MAC address        Expires
192.168.1.10     00:1a:2b:3c:4d:0a  58s
```

Run a second client with a different IP (e.g. `cargo run -- client 192.168.1.101`) and look up `192.168.1.100`. The server learned that address from the first client's request, so it can answer.

### Files

- `src/main.rs`: command-line entry point
- `src/server.rs`: UDP server with the ARP table
- `src/client.rs`: interactive resolver
- `src/cache.rs`: ARP cache with expiry
- `src/packet.rs`: ARP packet encoding and decoding
