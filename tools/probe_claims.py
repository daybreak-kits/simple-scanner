#!/usr/bin/env python3
"""Two claims to settle with data.

CLAIM A (from research report, item 5): "2759 port/s x 300 pool ~= 0.108s
average timeout; shrinking the timeout to 0.1s or 0.05s gives a linear 2-3x
throughput gain."
  -> If the timeout were binding, throughput would be exactly pool/timeout.
     Measure throughput across timeouts. If flat, the claim is a unit error.

CLAIM B (from research report, item 1): SO_LINGER(0) avoids TIME_WAIT and is
therefore a throughput win.
  -> Count actual TIME_WAIT sockets after a scan with and without SO_LINGER.
"""
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import gevent
from gevent import pool as gpool

PORTS = list(range(10000, 14000))


def scan(ports, conc, timeout, linger=False):
    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if linger:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        try:
            s.connect_ex(('127.0.0.1', port))
        finally:
            s.close()

    t = time.time()
    list(gpool.Pool(conc).imap(probe, ports))
    return time.time() - t


def timewait_count():
    """Count TIME_WAIT sockets from /proc (no iproute2 in this container)."""
    n = 0
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            with open(path) as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) > 3 and parts[3] == '06':   # 06 = TIME_WAIT
                        n += 1
        except OSError:
            pass
    return n


print('=== CLAIM A: is the timeout binding? (conc=300, %d closed ports) ===' % len(PORTS))
print('   if binding: throughput == conc / timeout')
print('  %-10s %8s %10s %14s' % ('timeout', 'wall', 'port/s', 'conc/timeout'))
for to in (0.05, 0.1, 0.25, 0.5, 1.0):
    el = scan(PORTS, 300, to)
    print('  %-10.2f %7.2fs %10.0f %14.0f' % (to, el, len(PORTS) / el, 300 / to))

print('\n=== CLAIM B: does TIME_WAIT accumulate? (%d closed ports) ===' % len(PORTS))
for linger in (False, True):
    before = timewait_count()
    scan(PORTS, 300, 1.0, linger=linger)
    time.sleep(0.2)
    after = timewait_count()
    print('  SO_LINGER(0)=%-5s  TIME_WAIT before=%4d  after=%4d  delta=%+d'
          % (linger, before, after, after - before))

print('\n  (a CLOSED port never enters TIME_WAIT: the kernel sends RST in')
print('   response to our SYN, so the connection is never established.)')
