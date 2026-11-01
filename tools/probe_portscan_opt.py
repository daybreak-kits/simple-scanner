#!/usr/bin/env python3
"""Port-scan speed: baseline vs three candidate optimisations.

Baseline is network.Scanner.handle_tcp_socket (network.py:407-449) verbatim.
Candidates:
  A. close the socket on the early-return path (it currently leaks an fd per
     closed port, because shutdown() raises OSError and we `return` before close)
  B. SO_LINGER {1,0} so the close sends RST instead of entering TIME_WAIT
  C. raw epoll batching: non-blocking connect + one poll() for N sockets,
     instead of one greenlet per connection
"""
import socket
import struct
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import select
from utils import network

N_PORTS = 18000
PORTS = list(range(10000, 10000 + N_PORTS))


# ---------------------------------------------------------------- baseline
def baseline(ip, ports, timeout=1.0):
    out = []
    for port in ports:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        ret = client.connect_ex((ip, port))
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            continue                      # ← fd leaked here in the shipped code
        client.close()
        if ret != 0:
            continue
        out.append(port)
    return out


# ---------------------------------------------------------------- A: fix leak
def fixed_leak(ip, ports, timeout=1.0):
    out = []
    for port in ports:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        try:
            ret = client.connect_ex((ip, port))
            if ret == 0:
                out.append(port)
        finally:
            client.close()
    return out


# ---------------------------------------------------------------- B: + SO_LINGER
def with_linger(ip, ports, timeout=1.0):
    out = []
    linger = struct.pack('ii', 1, 0)
    for port in ports:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        try:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
            if client.connect_ex((ip, port)) == 0:
                out.append(port)
        finally:
            client.close()
    return out


# ---------------------------------------------------------------- C: epoll batch
def epoll_batch(ip, ports, batch=2000, timeout=1.0):
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
        # one poll for the whole batch
        poller = select.poll()
        for s, _ in socks:
            poller.register(s, select.POLLOUT | select.POLLERR | select.POLLHUP)
        deadline = time.time() + timeout
        pending = len(socks)
        done = set()
        while pending > 0:
            remain = deadline - time.time()
            if remain <= 0:
                break
            events = poller.poll(max(1, int(remain * 1000)))
            if not events:
                break
            for fd, ev in events:
                done.add(fd)
            pending = len(socks) - len(done)
        for s, port in socks:
            try:
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    out.append(port)
            except OSError:
                pass
            finally:
                s.close()
    return out


# ---------------------------------------------------------------- ground truth
truth = []
for p in PORTS:
    s = socket.socket()
    s.settimeout(0.3)
    if s.connect_ex(('127.0.0.1', p)) == 0:
        truth.append(p)
    s.close()

print('=== %d ports on loopback (ephemeral range is %s, so no self-connect) ==='
      % (N_PORTS, open('/proc/sys/net/ipv4/ip_local_port_range').read().strip()))
print('  ground truth open: %d\n' % len(truth))
print('  %-24s %8s %10s %10s' % ('variant', 'wall', 'port/s', 'found'))

for name, fn in (('baseline (shipped)', baseline),
                 ('A fix fd leak', fixed_leak),
                 ('B + SO_LINGER', with_linger),
                 ('C epoll batch (2000)', epoll_batch)):
    t = time.time()
    found = fn('127.0.0.1', PORTS)
    el = time.time() - t
    flag = '' if sorted(found) == sorted(truth) else '  MISMATCH'
    print('  %-24s %7.2fs %10.0f %10d%s' % (name, el, N_PORTS / el, len(found), flag))
