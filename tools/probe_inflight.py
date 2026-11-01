#!/usr/bin/env python3
"""Why is peak in-flight only ~59 when the pool is 300?

Sequential connect to a closed loopback port costs 408 us. At 300 concurrent
that implies 735k port/s. Measured is 2.4k. So concurrency is not being
achieved. Test the candidate mechanisms one at a time:

  H1 settimeout() forces gevent to arm a timer per socket, and the hub's
     timer handling is the bottleneck.
  H2 the kernel serialises loopback RST handling (accept/SYN queue contention)
  H3 gevent Pool.imap has its own serialisation
"""
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

import gevent
from gevent import pool as gpool
from gevent import socket as gsocket

PORTS = list(range(10000, 14000))
state = {'now': 0, 'peak': 0}


def probe_timeout(port):
    state['now'] += 1
    state['peak'] = max(state['peak'], state['now'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)                      # <-- H1: arms a timer
    try:
        s.connect_ex(('127.0.0.1', port))
    finally:
        s.close()
        state['now'] -= 1


def probe_notimeout(port):
    state['now'] += 1
    state['peak'] = max(state['peak'], state['now'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect_ex(('127.0.0.1', port))   # no timer; gevent still yields
    finally:
        s.close()
        state['now'] -= 1


def probe_getsoerror(port):
    """Non-blocking + getsockopt instead of timeout: no per-socket timer."""
    state['now'] += 1
    state['peak'] = max(state['peak'], state['now'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.connect_ex(('127.0.0.1', port))
        from gevent import socket as gsocket
        gsocket.wait_write(s.fileno(), timeout=1.0)
        s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    finally:
        s.close()
        state['now'] -= 1


print('=== %d closed loopback ports, pool=300 ===' % len(PORTS))
print('  %-28s %8s %10s %12s' % ('variant', 'wall', 'port/s', 'peak in-flight'))
for name, fn in (('settimeout(1.0)', probe_timeout),
                 ('no timeout (gevent blocking)', probe_notimeout),
                 ('nonblocking + wait_write', probe_getsoerror)):
    state['now'] = 0
    state['peak'] = 0
    t = time.time()
    try:
        list(gpool.Pool(300).imap(fn, PORTS))
        el = time.time() - t
        print('  %-28s %7.2fs %10.0f %12d' % (name, el, len(PORTS) / el, state['peak']))
    except Exception as e:
        print('  %-28s FAILED %s' % (name, type(e).__name__))

# H2: is the kernel the limit? same load with plain threads, no gevent
print('\n=== control: 300 OS threads (no gevent at all) ===')
import threading
state['now'] = 0
state['peak'] = 0
lock = threading.Lock()


def tprobe(port):
    with lock:
        state['now'] += 1
        state['peak'] = max(state['peak'], state['now'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect_ex(('127.0.0.1', port))
    finally:
        s.close()
        with lock:
            state['now'] -= 1


sem = threading.Semaphore(300)


def run(port):
    with sem:
        tprobe(port)


t = time.time()
ths = [threading.Thread(target=run, args=(p,)) for p in PORTS]
for th in ths:
    th.start()
for th in ths:
    th.join()
el = time.time() - t
print('  %-28s %7.2fs %10.0f %12d' % ('300 threads', el, len(PORTS) / el, state['peak']))
