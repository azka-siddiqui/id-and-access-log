"""
log_generator.py

A small helper that appends synthetic log lines to a file over time so the
real-time monitor has something live to follow. It is only meant for local
demos and testing; in a real deployment the log file would be written by the
systems being monitored (sshd, a firewall, an app server, etc.).

The generator mixes normal traffic with two attack scenarios so the detectors
have something to catch:

  * a brute-force burst  -> many LOGIN_FAILED from one IP (threshold rule)
  * a scan-then-login    -> PORT_SCAN followed by LOGIN_FAILED (correlation)

Run standalone:
    python log_generator.py logs/live.log
"""

import os
import sys
import time
import random
from datetime import datetime

NORMAL_IPS = ["10.0.0.5", "10.0.0.6", "192.168.1.20", "192.168.1.21"]
ATTACKER_IP = "203.0.113.42"
SCANNER_IP = "198.51.100.7"
USERS = ["alice", "bob", "carol", "dave", "root", "admin"]
NORMAL_EVENTS = ["LOGIN_SUCCESS", "LOGOUT", "LOGIN_FAILED"]


def _line(ip, event, user):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{ts}, IP={ip}, EVENT={event}, USER={user}\n"


def _append(path, line):
    with open(path, "a") as f:
        f.write(line)
        f.flush()


def generate(path, duration=8.0, interval=0.15):
    """Stream synthetic events to `path` for roughly `duration` seconds."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    # Start the file fresh so a demo run is self-contained.
    open(path, "w").close()

    end = time.time() + duration
    tick = 0
    while time.time() < end:
        tick += 1

        # Mostly benign background traffic.
        _append(path, _line(
            random.choice(NORMAL_IPS),
            random.choices(NORMAL_EVENTS, weights=[6, 3, 1])[0],
            random.choice(USERS),
        ))

        # Every ~10 ticks, fire a brute-force burst from the attacker IP.
        if tick % 10 == 0:
            for _ in range(6):
                _append(path, _line(ATTACKER_IP, "LOGIN_FAILED", "root"))

        # Every ~17 ticks, fire a scan-then-login-failed correlation pattern.
        if tick % 17 == 0:
            _append(path, _line(SCANNER_IP, "PORT_SCAN", "admin"))
            _append(path, _line(SCANNER_IP, "LOGIN_FAILED", "admin"))

        time.sleep(interval)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join("logs", "live.log")
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    print(f"Generating synthetic logs to '{target}' for {secs}s...")
    generate(target, duration=secs)
    print("Done generating.")
