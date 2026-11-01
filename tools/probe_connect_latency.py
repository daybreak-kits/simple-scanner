#!/usr/bin/env python3
"""Why does a loopback connect to a CLOSED port appear to take ~0.1s?

300 greenlets / 2395 port/s implies 0.125s per connect, yet CPU is only
291 us/port. 99.8% of the wall time would be waiting on something. On loopback
a closed port returns RST immediately, so this does not add up. Measure it.
"""
import socket
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from gevent import monkey
monkey.patch_all(thread=False, httplib=True)

from utils import network

print('DEFAULT_SOCKET_TIMEOUT =', network.DEFAULT_SOCKET_TIMEOUT)

# ---- single-threaded latency, no gevent pool
PORTS = list(range(10000, 10300))
lat = []
for port in PORTS:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    t = time.perf_counter()
    rc = s.connect_ex(('127.0.0.1', port))
    lat.append(time.perf_counter() - t)
    s.close()

lat.sort()
print('\n=== 300 sequential connects to CLOSED loopback ports ===')
print('  median %.1f us   p90 %.1f us   max %.1f us   rc set=%s'
      % (lat[len(lat) // 2] * 1e6, lat[int(len(lat) * .9)] * 1e6,
         lat[-1] * 1e6, sorted({rc})[:3]))

# ---- same but through the shipped handle_tcp_socket
lat2 = []
for port in PORTS:
    t = time.perf_counter()
    network.Scanner.handle_tcp_socket('127.0.0.1', port, timeout=1.0)
    lat2.append(time.perf_counter() - t)
lat2.sort()
print('\n=== 300 sequential calls to shipped handle_tcp_socket ===')
print('  median %.1f us   p90 %.1f us   max %.1f us'
      % (lat2[len(lat2) // 2] * 1e6, lat2[int(len(lat2) * .9)] * 1e6, lat2[-1] * 1e6))

# ---- what does the shipped Scanner actually achieve, decomposed
print('\n=== implication ===')
print('  if per-connect latency is L and concurrency is C:')
print('    throughput = C / L          (latency bound)')
print('    throughput = 1 / cpu_per_port (cpu bound)')
print('  whichever is SMALLER wins. Compare the two.')
