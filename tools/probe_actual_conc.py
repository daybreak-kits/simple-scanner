#!/usr/bin/env python3
"""The numbers do not reconcile. Sequential connect to a closed loopback port
costs 408 us. With 300 concurrent that should be ~735,000 port/s. Measured is
2,395. So the greenlet pool is NOT achieving 300 in-flight connects.

Measure the actual in-flight count instead of assuming it.
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
inflight = {'now': 0, 'peak': 0}


def probe(port):
    inflight['now'] += 1
    inflight['peak'] = max(inflight['peak'], inflight['now'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect_ex(('127.0.0.1', port))
    finally:
        s.close()
        inflight['now'] -= 1


print('=== actual concurrency achieved by gevent Pool.imap ===')
print('  %-8s %8s %10s %12s %12s' % ('pool', 'wall', 'port/s', 'peak in-flight', 'implied conc'))
for conc in (50, 100, 300, 1000):
    inflight['now'] = 0
    inflight['peak'] = 0
    t = time.time()
    list(gpool.Pool(conc).imap(probe, PORTS))
    el = time.time() - t
    rate = len(PORTS) / el
    # implied concurrency = rate * per-connect latency (408us measured)
    implied = rate * 408e-6
    print('  %-8d %7.2fs %10.0f %12d %12.0f' % (conc, el, rate, inflight['peak'], implied))

print('\n=== same, but spawning greenlets directly (no Pool) ===')
for conc in (300, 1000):
    inflight['now'] = 0
    inflight['peak'] = 0
    t = time.time()
    batch = []
    for port in PORTS:
        batch.append(gevent.spawn(probe, port))
        if len(batch) >= conc:
            gevent.joinall(batch)
            batch = []
    gevent.joinall(batch)
    el = time.time() - t
    print('  %-8d %7.2fs %10.0f %12d' % (conc, el, len(PORTS) / el, inflight['peak']))
