#!/usr/bin/env python3
"""Settle it: is loopback port scanning CPU-bound or concurrency-bound?

Earlier I saw "peak in-flight only 59 with pool=300" and hypothesised that
concurrency was not being achieved, implying 5x headroom. Test that directly.

If throughput per port (~267 us) is already close to the pure CPU cost of
create+connect+close, then it is CPU bound and there is NO headroom, and the
low in-flight count is a CONSEQUENCE of being CPU bound, not a cause.
"""
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import gevent
from gevent import pool as gpool

PORTS = list(range(10000, 14000))


# ---- floor: socket create + close only, no connect at all
def floor_only(ports):
    for _ in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()


t = time.time()
floor_only(PORTS)
el = time.time() - t
floor_us = el * 1e6 / len(PORTS)
print('=== cost decomposition, %d loopback ports ===' % len(PORTS))
print('  create+close only (no connect)      : %6.0f us/port   -> %6.0f port/s'
      % (floor_us, 1e6 / floor_us))


# ---- sequential connect
def seq(ports):
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect_ex(('127.0.0.1', port))
        finally:
            s.close()


t = time.time()
seq(PORTS)
el = time.time() - t
seq_us = el * 1e6 / len(PORTS)
print('  sequential connect                  : %6.0f us/port   -> %6.0f port/s'
      % (seq_us, 1e6 / seq_us))


# ---- concurrent, various pools
print('\n  %-12s %8s %10s %14s %14s' % ('pool', 'wall', 'port/s', 'us/port', 'vs sequential'))
for conc in (50, 100, 300, 1000, 3000):
    t = time.time()
    list(gpool.Pool(conc).imap(
        lambda p: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close(), []))
    # real run
    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect_ex(('127.0.0.1', port))
        finally:
            s.close()

    t = time.time()
    list(gpool.Pool(conc).imap(probe, PORTS))
    el = time.time() - t
    us = el * 1e6 / len(PORTS)
    print('  %-12d %7.2fs %10.0f %14.0f %13.2fx' % (conc, el, len(PORTS) / el, us, seq_us / us))

print('\n  => if "us/port" stops falling as pool grows, the work is CPU bound')
print('     and adding concurrency cannot help.')
