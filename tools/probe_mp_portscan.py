#!/usr/bin/env python3
"""Port scan is CPU-bound at ~500 us/port in ONE process (single core).
That means the fix is not epoll, it is using more cores. Verify by running
N independent processes, each scanning a disjoint port range.

Also decompose the 500 us: is it syscall, or Python/gevent overhead?
If Python overhead dominates, per-process scaling is the only lever.
"""
import multiprocessing as mp
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import gevent
from gevent import pool as gpool

IP = '192.168.255.128'


def worker(args):
    lo, hi, conc = args
    ports = list(range(lo, hi))
    n = 0

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect_ex((IP, port))
        finally:
            s.close()

    c0 = time.process_time()
    t = time.time()
    list(gpool.Pool(conc).imap(probe, ports))
    return len(ports), time.time() - t, time.process_time() - c0


if __name__ == '__main__':
    TOTAL = 20000
    BASE = 20000
    CONC = 300
    print('=== port scan across N processes, %d ports, conc=%d/proc ===' % (TOTAL, CONC))
    print('  %-8s %10s %12s %14s %14s'
          % ('procs', 'wall', 'port/s', 'cpu s/proc', 'total cpu s'))
    for nproc in (1, 2, 4, 8):
        step = TOTAL // nproc
        jobs = [(BASE + i * step, BASE + (i + 1) * step, CONC) for i in range(nproc)]
        t = time.time()
        with mp.Pool(nproc) as p:
            res = p.map(worker, jobs)
        el = time.time() - t
        cpu = sum(r[2] for r in res)
        print('  %-8d %9.2fs %12.0f %14.2f %14.2f'
              % (nproc, el, TOTAL / el, cpu / nproc, cpu))
