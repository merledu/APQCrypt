"""
stress_test.py — makes the CPU busy on purpose, so we can test
whether the Policy Engine correctly switches to lighter algorithms
when resources are tight (the "CONSTRAINED" branch).

HOW TO USE (simple steps):
1. Open a SECOND terminal (keep your `python3 app.py` running in the first one).
2. In this second terminal, run:
       python3 stress_test.py
3. While it's running, go to your browser and click "Start pipeline" as usual.
4. Let the pipeline finish, then check policy.csv / the dashboard.
5. Come back to this terminal and press Ctrl+C to stop the stress test.

WHAT IT DOES:
It opens several worker processes that just do pointless heavy math
in a loop, forever, until you stop it. This pushes your CPU usage up
(you should see it above 50% — our CONSTRAINED threshold — while
this is running). It does NOT touch your files, network, or the
pipeline itself. It's just there to make the CPU look busy.
"""

import multiprocessing
import time
import sys

try:
    import psutil
except ImportError:
    psutil = None


def burn_cpu():
    """One worker: just does useless math forever to keep a CPU core busy."""
    x = 0
    while True:
        x += 1
        _ = x * x % 999983  # pointless math, just to burn CPU cycles


def main():
    num_workers = max(2, multiprocessing.cpu_count() - 1)  # leave 1 core free
    print(f"Starting {num_workers} CPU-burning workers...")
    print("Press Ctrl+C to stop.\n")

    workers = []
    for _ in range(num_workers):
        p = multiprocessing.Process(target=burn_cpu, daemon=True)
        p.start()
        workers.append(p)

    try:
        while True:
            time.sleep(2)
            if psutil:
                cpu = psutil.cpu_percent(interval=0.5)
                mem = psutil.virtual_memory().percent
                status = "CONSTRAINED" if cpu >= 50.0 or mem >= 70.0 else "AVAILABLE"
                print(f"CPU: {cpu:5.1f}%   Memory: {mem:5.1f}%   -> Resource status right now: {status}")
            else:
                print("(psutil not installed, can't show live CPU% here, but workers are running)")
    except KeyboardInterrupt:
        print("\nStopping stress test...")
        for p in workers:
            p.terminate()
        sys.exit(0)


if __name__ == "__main__":
    main()
