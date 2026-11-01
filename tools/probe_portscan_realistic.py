#!/usr/bin/env python3
"""Port scan: measure the RTT-independent cost, then the timeout scenario.

The loopback test measured pure syscall overhead (RTT ~ 0), which does not
transfer to a real network. Two measurements that DO transfer:

  1. CPU seconds per port  (RTT-independent; on a real network this is
     amortised across the RTT, so it only matters when it exceeds RTT/conc)
  2. Behaviour on FILTERED ports (packets dropped -> full timeout). This is
     the realistic worst case and it is decided by concurrency, not syscalls.
"""
import select
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

from gevent import pool as gpool

# TEST-NET-1 (RFC 5737): reserved for documentation, never routed.
# Every connect here hangs until timeout -> simulates a filtered port.
FILTERED_IP = '192.0.2.1'


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


# ------------------------------------------------------------------ 1. CPU per port
PORTS = list(range(10000, 16000))
print('=== 1. CPU cost per port, loopback, %d ports ===' % len(PORTS))
print('    (RTT-independent; this is what you pay regardless of network)')
print('  %-30s %8s %10s %12s' % ('variant', 'wall', 'port/s', 'us CPU/port'))
for name, fn in (('greenlet pool=300', lambda: greenlet_scan('127.0.0.1', PORTS, 300, 1.0)),
                 ('greenlet pool=1000', lambda: greenlet_scan('127.0.0.1', PORTS, 1000, 1.0)),
                 ('epoll batch=1000', lambda: epoll_scan('127.0.0.1', PORTS, 1000, 1.0))):
    c0 = time.process_time()
    t = time.time()
    fn()
    el = time.time() - t
    cpu = time.process_time() - c0
    print('  %-30s %7.2fs %10.0f %12.1f' % (name, el, len(PORTS) / el, cpu * 1e6 / len(PORTS)))

# ------------------------------------------------------------------ 2. filtered ports
PORTS_F = list(range(10000, 10400))
TIMEOUT = 1.0
print('\n=== 2. FILTERED ports (packets dropped, full %.0fs timeout) ===' % TIMEOUT)
print('    %d ports to %s; ideal wall = ports/conc * timeout' % (len(PORTS_F), FILTERED_IP))
print('  %-30s %8s %10s %12s' % ('variant', 'wall', 'port/s', 'ideal'))
for conc in (100, 300, 1000):
    ideal = len(PORTS_F) / conc * TIMEOUT
    t = time.time()
    greenlet_scan(FILTERED_IP, PORTS_F, conc, TIMEOUT)
    el = time.time() - t
    print('  greenlet pool=%-6d            %7.2fs %10.0f %11.2fs' % (conc, el, len(PORTS_F) / el, ideal))
for batch in (100, 1000):
    ideal = len(PORTS_F) / batch * TIMEOUT
    t = time.time()
    epoll_scan(FILTERED_IP, PORTS_F, batch, TIMEOUT)
    el = time.time() - t
    print('  epoll batch=%-6d             %7.2fs %10.0f %11.2fs' % (batch, el, len(PORTS_F) / el, ideal))
