#!/usr/bin/env python3
"""Does one slow task block every later result?

utils/process.py yield_result():
    self.jobs.reverse()
    while self.jobs:
        yield self.jobs.pop().result(timeout)   # timeout=None

pop() after reverse() takes the FIRST submitted future, and .result(None)
blocks until it finishes. So a slow task #0 withholds the results of tasks
1..N that already completed.
"""
import sys
import time

sys.path.insert(0, '/opt/workspace/labs/simple-scanner')
from utils import process


def work(delay):
    time.sleep(delay)
    return delay


pool = process.new(max_workers=8)
# task 0 is slow, tasks 1..7 are fast
pool.sm(work, 3.0)
for _ in range(7):
    pool.sm(work, 0.05)

t0 = time.time()
arrivals = []
for value in pool.yield_result():
    arrivals.append((round(time.time() - t0, 2), value))

print('=== 8 tasks: #0 takes 3.0s, #1..#7 take 0.05s each ===')
print('  result arrival order (seconds since iteration start, value):')
for when, val in arrivals:
    print('    t=%.2fs  task(%.2fs)' % (when, val))

first_fast = next((w for w, v in arrivals if v != 3.0), None)
print('\n  the 7 fast tasks actually finished at ~0.05s')
print('  but the first of them was only *delivered* at t=%.2fs' % (first_fast or -1))
print('  verdict: %s' % ('HEAD-OF-LINE BLOCKING confirmed'
                         if first_fast and first_fast > 2.5 else 'no blocking'))
