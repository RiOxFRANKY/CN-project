"""Accept one TCP client on listen_port, forward to target_port, and record
each direction to <prefix>.c2s / <prefix>.s2c, plus an ordered chunk log."""
import socket, sys, threading
listen_port, target_port, prefix = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
log, lock = [], threading.Lock()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", listen_port)); srv.listen(1)
cli, _ = srv.accept()
up = socket.create_connection(("127.0.0.1", target_port))
def pump(a, b, tag):
    while True:
        d = a.recv(65536)
        if not d: break
        with lock: log.append((tag, d))
        b.sendall(d)
    try: b.shutdown(socket.SHUT_WR)
    except OSError: pass
t1 = threading.Thread(target=pump, args=(cli, up, "c2s")); t2 = threading.Thread(target=pump, args=(up, cli, "s2c"))
t1.start(); t2.start(); t1.join(); t2.join()
for tag in ("c2s", "s2c"):
    open(f"{prefix}.{tag}", "wb").write(b"".join(d for t, d in log if t == tag))
with open(f"{prefix}.log", "w") as f:
    for t, d in log: f.write(f"{t} {d.hex()}\n")
