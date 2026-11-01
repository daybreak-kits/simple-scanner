#!/usr/bin/env python3
"""Is the 1500 port/s ceiling OUR cost or the TARGET's?

Earlier data: at pool=50, effective latency was 65 ms, but a single connect
measures 12.8 ms. If latency inflates with concurrency, the target (or the
path) is queueing our SYNs, and no client-side optimisation helps.

Measure the per-connect latency DISTRIBUTION at each concurrency level.
  flat latency  -> we are the bottleneck (CPU/scheduler) -> optimise client
  inflating     -> target is the bottleneck -> optimise nothing, cap concurrency
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
PORTS = list(range(20000, 24000))     # 4000 closed ports


def run(conc):
    lat = []
    lock = gevent.lock.Semaphore()

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        t = time.perf_counter()
        try:
            s.connect_ex((IP, port))
        finally:
            s.close()
            with lock:
                lat.append(time.perf_counter() - t)

    t0 = time.time()
    list(gpool.Pool(conc).imap(probe, PORTS))
    el = time.time() - t0
    lat.sort()
    n = len(lat)
    return (el, n / el, lat[n // 2] * 1000, lat[int(n * .9)] * 1000,
            lat[int(n * .99)] * 1000, lat[-1] * 1000)


print('=== %s, %d closed ports: latency vs concurrency ===' % (IP, len(PORTS)))
print('  %-6s %8s %10s %10s %10s %10s %10s'
      % ('conc', 'wall', 'port/s', 'p50 ms', 'p90 ms', 'p99 ms', 'max ms'))
for conc in (1, 10, 50, 200, 500, 1000):
    el, rate, p50, p90, p99, mx = run(conc)
    print('  %-6d %7.2fs %10.0f %10.1f %10.1f %10.1f %10.1f'
          % (conc, el, rate, p50, p90, p99, mx))
