"""
main.py

Entry point for the Security Log Analysis & Intrusion Detection system.

Two modes are supported:

  batch     Read an existing log file once, top to bottom, run threshold and
            correlation detection, and write any alerts to the output file.
            (This is the original, single-pass behaviour.)

  realtime  Follow a log file as it grows (like `tail -f`) using a
            multithreaded producer/consumer pipeline: one thread tails the
            file and enqueues new lines, while worker threads parse events and
            run detection concurrently on a rolling time window. Alerts are
            printed as they happen and appended to the output file.

Examples:
    python main.py                                 # batch over logs/sample.log
    python main.py --mode realtime --seconds 8     # follow a live log for 8s
    python main.py --mode realtime --log logs/live.log --workers 3
"""

import os
import argparse
import threading

from parser import parse_log_line
from anomaly import detect_threshold_anomalies
from correlation import correlate_events
from ingest import RealTimeMonitor


DEFAULT_LOG = os.path.join("logs", "sample.log")
DEFAULT_OUTPUT = os.path.join("output", "suspicious_events.txt")


def _reset_output(output_file):
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    if os.path.exists(output_file):
        os.remove(output_file)


def run_batch(log_file, output_file):
    """Original single-pass mode: read the whole file, then detect."""
    _reset_output(output_file)

    parsed_events = []
    with open(log_file, "r") as log_f:
        for line in log_f:
            event_data = parse_log_line(line)
            if event_data:
                parsed_events.append(event_data)

            # Every 10 events, run detection over everything seen so far.
            if len(parsed_events) % 10 == 0:
                alerts = (detect_threshold_anomalies(parsed_events)
                          + correlate_events(parsed_events))
                if alerts:
                    with open(output_file, "a") as out_f:
                        for alert in alerts:
                            out_f.write(alert + "\n")

    print(f"Done processing logs. Check '{output_file}' for alerts.")


def run_realtime(log_file, output_file, workers, seconds):
    """Multithreaded mode: follow the log live and detect concurrently."""
    _reset_output(output_file)

    # Guard the output file across the printing thread and workers.
    file_lock = threading.Lock()

    def alert_sink(alert, worker_id):
        print(f"[worker {worker_id}] {alert}")
        with file_lock:
            with open(output_file, "a") as out_f:
                out_f.write(alert + "\n")

    monitor = RealTimeMonitor(
        log_path=log_file,
        alert_sink=alert_sink,
        num_workers=workers,
    )

    print(f"Following '{log_file}' in real time with {workers} worker(s) "
          f"for {seconds}s... (Ctrl+C to stop early)")
    monitor.run_for(seconds)
    print(f"Stopped. Alerts written to '{output_file}'.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Security log analysis & intrusion detection."
    )
    parser.add_argument("--mode", choices=["batch", "realtime"], default="batch",
                        help="batch = single pass; realtime = follow the log live")
    parser.add_argument("--log", default=DEFAULT_LOG,
                        help=f"path to the log file (default: {DEFAULT_LOG})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"where to write alerts (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--workers", type=int, default=2,
                        help="number of detection worker threads (realtime mode)")
    parser.add_argument("--seconds", type=float, default=8.0,
                        help="how long to follow the log in realtime mode")
    return parser


def main():
    args = build_parser().parse_args()
    if args.mode == "realtime":
        run_realtime(args.log, args.output, args.workers, args.seconds)
    else:
        run_batch(args.log, args.output)


if __name__ == "__main__":
    main()
