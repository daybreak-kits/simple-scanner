#!/usr/bin/env python3
"""On the REAL target, find out what actually limits port-scan throughput.

Ground truth: 192.168.255.128 has 4 open ports, RST RTT median 12.84 ms.
At pool=500 we measured 1772 port/s => Little's law says only ~23 in flight,
not 500. Reproduce that and sweep the pool to find the real ceiling.

Three candidate ceilings, each with a distinct signature:
  L  latency-bound  : throughput grows linearly with pool, in-flight == pool
  C  CPU-bound      : throughput flat while pool grows, in-flight << pool
  S  serialised     : throughput flat AND in-flight flat (~constant k)
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
PORTS = list(range(20000, 40000))          # 20k closed ports, no open ones
state = {'now': 0, 'peak': 0}
lock = gevent.lock.Semaphore()


def probe(port):
    state['now'] += 1
    if state['now'] > state['peak']:
        state['peak'] = state['now']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect_ex((IP, port))
    finally:
        s.close()
        state['now'] -= 1


print('=== real target %s, %d closed ports ===' % (IP, len(PORTS)))
print('  %-8s %8s %10s %14s %12s %12s'
      % ('pool', 'wall', 'port/s', 'peak in-flight', 'implied RTT', 'cpu us/port'))
for conc in (50, 100, 300, 500, 1000, 2000):
    state['now'] = 0
    state['peak'] = 0
    c0 = time.process_time()
    t = time.time()
    list(gpool.Pool(conc).imap(probe, PORTS))
    el = time.time() - t
    cpu = time.process_time() - c0
    rate = len(PORTS) / el
    # Little's law: in-flight = throughput x latency
    implied_rtt = state['peak'] / rate if rate else 0
    print('  %-8d %7.2fs %10.0f %14d %11.1fms %12.0f'
          % (conc, el, rate, state['peak'], implied_rtt * 1000, cpu * 1e6 / len(PORTS)))
