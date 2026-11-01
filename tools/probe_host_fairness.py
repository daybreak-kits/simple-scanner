#!/usr/bin/env python3
"""Port scan scheduling: does host-fairness help, and which shape implements it?

Two rounds of measurement already happened. Results so far:

Round 1 (wrong model — assumed host-major "A finishes then B"):
    host-major    3.80s  1052 probe/s
    round-robin   2.30s  1739 probe/s   <- looked 1.65x faster
    => WRONG, because the real code is not host-major

Round 2 (correct model — real code submits ALL hosts' ports into ONE shared
pool synchronously, then drains FIFO):
    FIFO on shared pool (current)  2.62s  1525 probe/s
    interleaved submit             3.52s  1135 probe/s   <- 34% SLOWER
    per-host pool 75 each          3.21s  1247 probe/s   <- 23% SLOWER
    => interleaving HURTS. FIFO is fastest.

So "reduce per-target pressure" is a real goal, but changing submission order
is the wrong lever. The correct lever is capping IN-FLIGHT per host while
keeping FIFO submission. That is what round 3 measures.
"""
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import gevent
from gevent import pool as gpool

REAL = '192.168.255.128'
LOOP = '127.0.0.1'
HOSTS = [REAL, LOOP, REAL, LOOP]
PORTS = list(range(20000, 21000))


def probe(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect_ex((host, port))
    finally:
        s.close()


def fifo_shared_pool(pool_size):
    """Exactly what ss.py:190 + network.py:476-482 do now."""
    p = gpool.Pool(pool_size)
    t = time.time()
    for host in HOSTS:
        for port in PORTS:
            p.spawn(probe, host, port)
    p.join()
    return time.time() - t


def per_host_cap(pool_size, per_host):
    """FIFO submission + per-host in-flight semaphore.

    This is the only shape that actually lowers per-target pressure: at most
    per_host sockets are open against any single host at any instant, no matter
    how many hosts share the pool. Submission order stays FIFO.
    """
    t = time.time()
    sems = {}

    def sem_for(host):
        if host not in sems:
            sems[host] = gevent.lock.Semaphore(per_host)
        return sems[host]

    def guarded(host, port):
        with sem_for(host):
            probe(host, port)

    p = gpool.Pool(pool_size)
    for host in HOSTS:
        for port in PORTS:
            p.spawn(guarded, host, port)
    p.join()
    return time.time() - t


N = len(HOSTS) * len(PORTS)
print('=== %d hosts x %d ports = %d probes ===' % (len(HOSTS), len(PORTS), N))
print('  %-38s %10s %12s' % ('strategy', 'wall', 'probe/s'))
for label, fn in (
    ('FIFO shared pool (current)', lambda: fifo_shared_pool(300)),
    ('per-host in-flight cap = 100', lambda: per_host_cap(300, 100)),
    ('per-host in-flight cap = 50', lambda: per_host_cap(300, 50)),
    ('per-host in-flight cap = 25', lambda: per_host_cap(300, 25)),
    ('per-host in-flight cap = 10', lambda: per_host_cap(300, 10)),
):
    el = fn()
    print('  %-38s %9.2fs %12.0f' % (label, el, N / el))
