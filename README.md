# CN-project

Computer Networks protocol implementations in Rust, using only the standard library.

| Folder | Protocol | Transport | Default port |
| --- | --- | --- | --- |
| [`telnet/`](telnet) | Telnet server and client | TCP | 2323 |
| [`arp/`](arp) | ARP server and client | UDP | 4000 |

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) (stable, with Cargo)

Each folder is its own Cargo project. Run the commands below from inside that folder, and use two terminals: one for the server, one for the client.

## Telnet

A multi-client Telnet server and an interactive client. Both sides handle Telnet `IAC` command bytes, refuse every option negotiation (`DO` → `WONT`, `WILL` → `DONT`), and escape `0xFF` in data.

```bash
cd telnet
cargo run -- server [port]
cargo run -- client [host] [port]
```

Server commands:

| Command | Reply |
| --- | --- |
| `help` | Lists the commands |
| `echo <text>` | Sends the text back |
| `time` | Seconds since the Unix epoch |
| `quit` / `exit` | Closes the connection |

Example session:

```text
Connected to 127.0.0.1:2323
Welcome to the Rust telnet server
Type 'help' for commands
> echo hello telnet
hello telnet
> quit
Goodbye
```

The server also works with any standard Telnet client, e.g. `telnet 127.0.0.1 2323`.

### Files

- `src/main.rs`: command-line entry point
- `src/server.rs`: TCP listener, one thread per client
- `src/client.rs`: interactive client
- `src/commands.rs`: server command handling
- `src/protocol.rs`: Telnet `IAC` parser and escaping

## ARP

Sending real ARP frames needs raw Ethernet access, so this version carries real 28-byte ARP packets (RFC 826 format: Ethernet/IPv4, request and reply) over UDP instead.

- The **server** holds an IP → MAC table, answers requests for addresses it knows, and learns the sender's IP and MAC from every request, as real ARP does.
- The **client** has its own IP and a MAC derived from it (`02:00:` + the IP bytes). It checks its **ARP cache** first, sends an ARP request on a miss, and caches the reply for 60 seconds.

```bash
cd arp
cargo run -- server [port]
cargo run -- client [my-ip] [server] [port]
```

Client input: an IPv4 address to resolve, `cache` to show the cache, or `quit`.

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
