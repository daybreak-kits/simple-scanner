#!/usr/bin/env python3
"""The decisive test: can epoll hold far more sockets in flight than greenlets?

On a real network most ports are filtered, so wall = ports/conc * timeout.
Throughput is therefore decided ENTIRELY by how much concurrency you can hold.
epoll keeps only an fd per socket; gevent keeps an fd + a greenlet stack.
"""
import resource
import select
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

from gevent import pool as gpool

FILTERED_IP = '192.0.2.1'      # RFC 5737 TEST-NET-1, never routed
TIMEOUT = 1.0


def greenlet_scan(ip, ports, conc, timeout):
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


def epoll_scan(ip, ports, batch, timeout):
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


soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
print('RLIMIT_NOFILE soft=%d hard=%d' % (soft, hard))
print('epoll can hold at most ~%d sockets; gevent also needs a stack each\n' % (soft - 20))

N = 5000
PORTS = list(range(10000, 10000 + N))
print('=== %d FILTERED ports, %.0fs timeout, ideal wall = 1 x timeout if all in flight ==='
      % (N, TIMEOUT))
print('  %-30s %8s %10s %14s' % ('variant', 'wall', 'port/s', 'in-flight'))

for conc in (1000, 3000, 5000):
    t = time.time()
    try:
        greenlet_scan(FILTERED_IP, PORTS, conc, TIMEOUT)
        el = time.time() - t
        print('  greenlet pool=%-6d            %7.2fs %10.0f %14d'
              % (conc, el, N / el, min(conc, N)))
    except Exception as e:
        print('  greenlet pool=%-6d            FAILED %s' % (conc, type(e).__name__))

for batch in (1000, 3000, 5000):
    t = time.time()
    try:
        epoll_scan(FILTERED_IP, PORTS, batch, TIMEOUT)
        el = time.time() - t
        print('  epoll batch=%-6d             %7.2fs %10.0f %14d'
              % (batch, el, N / el, min(batch, N)))
    except Exception as e:
        print('  epoll batch=%-6d             FAILED %s' % (batch, type(e).__name__))
