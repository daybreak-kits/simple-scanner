#!/usr/bin/env python3
"""Keep-alive HTTP counter server used by repro_defects.py.

Usage: python probe_server.py 18270 18271 ...
Writes {'conn': N, 'req': N} to /tmp/_repro_counters.json on SIGTERM.
"""
import json
import signal
import socket
import sys
import threading
import time

CRLF = b'\r\n'
COUNTERS = {'conn': 0, 'req': 0}
LOCK = threading.Lock()


def dump(*_args):
    with LOCK:
        with open('/tmp/_repro_counters.json', 'w') as f:
            f.write(json.dumps(COUNTERS))
    sys.exit(0)


def handle(conn):
    try:
        conn.settimeout(10)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            data = conn.recv(65535)
            if not data:
                break
            with LOCK:
                COUNTERS['req'] += 1
            conn.sendall(b'HTTP/1.1 200 OK' + CRLF + b'Content-Length: 2' + CRLF + CRLF + b'ok')
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(512)
    while True:
        try:
            conn, _ = srv.accept()
        except Exception:
            return
        with LOCK:
            COUNTERS['conn'] += 1
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, dump)
    for p in sys.argv[1:]:
        threading.Thread(target=serve, args=(int(p),), daemon=True).start()
    time.sleep(300)
