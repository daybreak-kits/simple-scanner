#!/usr/bin/env python3
"""Port scan: greenlet-per-connection (current) vs epoll batch, at matched
concurrency, so the comparison is about the mechanism and not about pool size.
"""
import select
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import gevent
from gevent import pool as gpool
from utils import network

PORTS = list(range(10000, 28000))


def greenlet_scan(ip, ports, conc, timeout=1.0):
    """Same mechanism as utils/network.py:482 (one greenlet per connect)."""
    out = []

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                out.append(port)
        finally:
            s.close()

    list(gpool.Pool(conc).imap(probe, ports))
    return out


def epoll_scan(ip, ports, batch=250, timeout=1.0):
    out = []
    for start in range(0, len(ports), batch):
        chunk = ports[start:start + batch]
        socks = []
        for port in chunk:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                s.connect_ex((ip, port))
            except BlockingIOError:
                pass
            socks.append((s, port))
        poller = select.poll()
        for s, _ in socks:
            poller.register(s, select.POLLOUT | select.POLLERR | select.POLLHUP)
        deadline = time.time() + timeout
        done = set()
        while len(done) < len(socks):
            remain = deadline - time.time()
            if remain <= 0:
                break
            ev = poller.poll(max(1, int(remain * 1000)))
            if not ev:
                break
            for fd, _ in ev:
                done.add(fd)
        for s, port in socks:
            try:
                if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    out.append(port)
            except OSError:
                pass
            finally:
                s.close()
    return out


truth = []
for p in PORTS:
    s = socket.socket()
    s.settimeout(0.3)
    if s.connect_ex(('127.0.0.1', p)) == 0:
        truth.append(p)
    s.close()

print('=== %d ports, %d actually open ===' % (len(PORTS), len(truth)))
print('  %-34s %8s %10s' % ('variant', 'wall', 'port/s'))
for conc in (100, 300, 1000, 3000):
    t = time.time()
    f = greenlet_scan('127.0.0.1', PORTS, conc)
    el = time.time() - t
    flag = '' if sorted(f) == sorted(truth) else ' MISMATCH'
    print('  greenlet per-conn, pool=%-6d      %7.2fs %10.0f%s' % (conc, el, len(PORTS) / el, flag))

for batch in (250, 1000):
    t = time.time()
    f = epoll_scan('127.0.0.1', PORTS, batch)
    el = time.time() - t
    flag = '' if sorted(f) == sorted(truth) else ' MISMATCH'
    print('  epoll batch=%-6d                 %7.2fs %10.0f%s' % (batch, el, len(PORTS) / el, flag))
