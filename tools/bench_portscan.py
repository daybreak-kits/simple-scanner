#!/usr/bin/env python3
"""Port-scan throughput with the scanner's REAL pool size (default 300)."""
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)
from utils import network

N = 30000
PORTS = list(range(30000, 30000 + N))

print('=== %d closed ports on loopback (RST path), Scanner pool size 300 ===' % N)
sc = network.Scanner()
t = time.time()
sc.scan_run('127.0.0.1', PORTS, is_check_alive=False, is_yield=False)
found = list(sc.get_yield_tcp())
el = time.time() - t
rate = N / el
print('  %d ports in %.2fs -> %.0f port/s' % (N, el, rate))
print('  open ports found: %d (expected 0)' % len(found))

per_host = len(network.DEFAULT_SCAN_PORTS)
print('\n  DEFAULT_SCAN_PORTS          : %d ports' % per_host)
for label, hosts in (('/24', 256), ('/16', 65536)):
    total = hosts * per_host
    print('  %-4s = %10d connect attempts -> %8.1f min at this rate'
          % (label, total, total / rate / 60))
