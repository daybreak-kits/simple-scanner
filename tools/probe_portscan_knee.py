#!/usr/bin/env python3
"""Two questions:
1. Does the shipped handle_tcp_socket really leak an fd per closed port?
2. What batch size is optimal for the epoll approach?
"""
import os
import resource
import socket
import select
import struct
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)


def open_fds():
    try:
        return len(os.listdir('/proc/self/fd'))
    except OSError:
        return -1


# ---------------------------------------------------------------- 1. fd leak
print('=== fd accounting: 2000 CLOSED ports ===')
before = open_fds()


def shipped(ip, ports):
    """network.py:407-449 verbatim: shutdown() raises -> return before close()."""
    for port in ports:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1.0)
        client.connect_ex((ip, port))
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            continue                    # ← no close()
        client.close()


shipped('127.0.0.1', list(range(10000, 12000)))
after = open_fds()
print('  fd before: %d   after: %d   leaked: %d' % (before, after, after - before))

# ---------------------------------------------------------------- 2. batch knee
PORTS = list(range(10000, 28000))


def epoll_batch(ip, ports, batch, timeout=1.0):
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
            events = poller.poll(max(1, int(remain * 1000)))
            if not events:
                break
            for fd, _ in events:
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

print('\n=== epoll batch size knee: %d ports, %d actually open ===' % (len(PORTS), len(truth)))
print('  %-10s %8s %10s %8s' % ('batch', 'wall', 'port/s', 'found'))
for batch in (250, 500, 1000, 2000, 4000, 8000):
    t = time.time()
    found = epoll_batch('127.0.0.1', PORTS, batch)
    el = time.time() - t
    ok = '' if sorted(found) == sorted(truth) else ' MISMATCH'
    print('  %-10d %7.2fs %10.0f %8d%s' % (batch, el, len(PORTS) / el, len(found), ok))
