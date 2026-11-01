#!/usr/bin/env python3
"""Concurrency-counter HTTP server: records peak simultaneous in-flight requests.

Usage: python peak_server.py <port>
Writes {'peak': N, 'total': N, 'conns': N} to /tmp/_peak.json on SIGTERM.
Each request is held for HOLD seconds so overlap is observable.
"""
import json
import os
import signal
import socket
import sys
import threading
import time

HOLD = float(os.environ.get('PEAK_HOLD', '0.20'))
CRLF = b'\r\n'
STATE = {'cur': 0, 'peak': 0, 'total': 0, 'conns': 0}
LOCK = threading.Lock()


def dump(*_a):
    with LOCK:
        open('/tmp/_peak.json', 'w').write(json.dumps(STATE))
    sys.exit(0)


def handle(conn):
    try:
        conn.settimeout(30)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            data = conn.recv(65535)
            if not data:
                break
            with LOCK:
                STATE['total'] += 1
                STATE['cur'] += 1
                if STATE['cur'] > STATE['peak']:
                    STATE['peak'] = STATE['cur']
            time.sleep(HOLD)
            conn.sendall(b'HTTP/1.1 200 OK' + CRLF + b'Content-Length: 2' + CRLF + CRLF + b'ok')
            with LOCK:
                STATE['cur'] -= 1
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
    srv.listen(1024)
    while True:
        try:
            conn, _ = srv.accept()
        except Exception:
            return
        with LOCK:
            STATE['conns'] += 1
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, dump)
    threading.Thread(target=serve, args=(int(sys.argv[1]),), daemon=True).start()
    time.sleep(600)
