#!/usr/bin/env python3
"""Ground truth for 192.168.255.128: full 1-65535 TCP connect scan.

Independent of simple-scanner. Uses a large greenlet pool + per-connect
timing, so we get both the open set and the RTT distribution. The RTT matters:
it decides whether port scanning here is latency-bound or CPU-bound.
"""
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import gevent
from gevent import pool as gpool

IP = '192.168.255.128'
PORTS = list(range(1, 65536))
open_ports = []
refused_rtt = []
timeouts = []
lock = gevent.lock.Semaphore()


def probe(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    t = time.perf_counter()
    rc = -1
    try:
        rc = s.connect_ex((IP, port))
    except OSError:
        rc = -1
    el = time.perf_counter() - t
    s.close()
    if rc == 0:
        with lock:
            open_ports.append((port, el))
    elif rc in (110, -1):
        with lock:
            timeouts.append(port)
    else:
        with lock:
            refused_rtt.append(el)


t0 = time.time()
list(gpool.Pool(500).imap(probe, PORTS))
elapsed = time.time() - t0

refused_rtt.sort()
print('=== ground truth: %s, ports 1-65535 ===' % IP)
print('  wall            : %.2fs  (%.0f port/s)' % (elapsed, len(PORTS) / elapsed))
print('  OPEN            : %d  -> %s' % (len(open_ports), sorted(p for p, _ in open_ports)))
print('  refused (RST)   : %d' % len(refused_rtt))
print('  timeout/no resp : %d  -> %s' % (len(timeouts), timeouts[:20]))
if refused_rtt:
    print('  RST RTT         : median %.2f ms  p90 %.2f ms  p99 %.2f ms  max %.2f ms'
          % (refused_rtt[len(refused_rtt) // 2] * 1000,
             refused_rtt[int(len(refused_rtt) * .9)] * 1000,
             refused_rtt[int(len(refused_rtt) * .99)] * 1000,
             refused_rtt[-1] * 1000))
print('\n  open port detail (port, connect latency):')
for port, lat in sorted(open_ports):
    print('    %-6d %.2f ms' % (port, lat * 1000))
