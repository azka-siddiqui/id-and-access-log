"""
ingest.py

Real-time, multithreaded log ingestion pipeline.

The design is a classic producer/consumer split, wired together with a
thread-safe queue.Queue:

    LogTailer (producer thread)
        Follows a log file the way `tail -f` does. As new lines are appended
        to the file, it reads them and puts the raw strings onto a shared
        queue. It never blocks the detection logic, so ingestion keeps up
        even while analysis is running.

    DetectionWorker (one or more consumer threads)
        Pull raw lines off the queue, parse them into structured events, keep
        a rolling in-memory window of recent events, and periodically run the
        threshold-based anomaly and event-correlation checks against that
        window. Alerts are written out under a lock so concurrent workers
        never interleave their output.

Shutdown is coordinated with a threading.Event: the tailer stops following,
drops a sentinel (None) on the queue for each worker, and the workers drain
and exit cleanly.
"""

import threading
import queue
import time
from datetime import timedelta

from parser import parse_log_line
from anomaly import detect_threshold_anomalies
from correlation import correlate_events


# Sentinel object pushed onto the queue to tell a worker to shut down.
_SHUTDOWN = None


class LogTailer(threading.Thread):
    """Producer thread that follows a log file and enqueues new lines.

    Behaves like `tail -f`: seeks to the end of the file (unless
    from_start=True), then blocks on new writes. Each appended line is placed
    on the shared queue for the detection workers to consume.
    """

    def __init__(self, log_path, line_queue, stop_event,
                 from_start=False, poll_interval=0.25):
        super().__init__(name="LogTailer", daemon=True)
        self.log_path = log_path
        self.queue = line_queue
        self.stop_event = stop_event
        self.from_start = from_start
        self.poll_interval = poll_interval

    def run(self):
        # Wait for the file to exist (a generator may create it slightly late).
        while not self._exists() and not self.stop_event.is_set():
            time.sleep(self.poll_interval)

        if self.stop_event.is_set():
            return

        with open(self.log_path, "r") as f:
            if not self.from_start:
                # Skip whatever is already in the file; only follow new lines.
                f.seek(0, 2)  # 2 == os.SEEK_END

            while not self.stop_event.is_set():
                line = f.readline()
                if line:
                    # Only enqueue complete lines (ending in newline). A partial
                    # write with no newline yet is left for the next poll.
                    if line.endswith("\n"):
                        self.queue.put(line.rstrip("\n"))
                    else:
                        # Rewind so we re-read this partial line once it's whole.
                        f.seek(f.tell() - len(line))
                        time.sleep(self.poll_interval)
                else:
                    # No new data right now; wait a beat and poll again.
                    time.sleep(self.poll_interval)

    def _exists(self):
        try:
            open(self.log_path, "r").close()
            return True
        except OSError:
            return False


class DetectionWorker(threading.Thread):
    """Consumer thread that parses lines and runs detection on a rolling window.

    Each worker keeps its own recent-events window and, every `run_every`
    parsed events, runs the threshold and correlation detectors. New alerts
    (deduplicated) are handed to `alert_sink`, which is called while holding a
    shared lock so output from multiple workers never interleaves.
    """

    def __init__(self, worker_id, line_queue, alert_sink, alert_lock,
                 window=timedelta(minutes=10), run_every=5):
        super().__init__(name=f"DetectionWorker-{worker_id}", daemon=True)
        self.worker_id = worker_id
        self.queue = line_queue
        self.alert_sink = alert_sink
        self.alert_lock = alert_lock
        self.window = window
        self.run_every = run_every

        self._events = []          # rolling window of parsed event dicts
        self._seen_alerts = set()  # dedupe so a standing alert isn't re-emitted
        self._since_last_run = 0

    def run(self):
        while True:
            item = self.queue.get()
            try:
                if item is _SHUTDOWN:
                    return
                self._handle_line(item)
            finally:
                # Always mark the task done, even on parse errors, so a
                # queue.join() on the producer side can't hang.
                self.queue.task_done()

    def _handle_line(self, line):
        event = parse_log_line(line)
        if not event:
            return

        self._events.append(event)
        self._prune_window(event["timestamp"])
        self._since_last_run += 1

        if self._since_last_run >= self.run_every:
            self._since_last_run = 0
            self._run_detection()

    def _prune_window(self, latest_time):
        """Drop events older than `window` relative to the newest event."""
        cutoff = latest_time - self.window
        self._events = [e for e in self._events if e["timestamp"] >= cutoff]

    def _run_detection(self):
        alerts = []
        alerts.extend(detect_threshold_anomalies(self._events))
        alerts.extend(correlate_events(self._events))

        # Emit only alerts we haven't reported yet.
        new_alerts = [a for a in alerts if a not in self._seen_alerts]
        if not new_alerts:
            return
        self._seen_alerts.update(new_alerts)

        # Serialize output across workers.
        with self.alert_lock:
            for alert in new_alerts:
                self.alert_sink(alert, self.worker_id)


class RealTimeMonitor:
    """Wires a LogTailer and a pool of DetectionWorkers into one pipeline."""

    def __init__(self, log_path, alert_sink, num_workers=2,
                 from_start=False, run_every=5, window=timedelta(minutes=10)):
        self.log_path = log_path
        self.alert_sink = alert_sink
        self.num_workers = max(1, num_workers)
        self.from_start = from_start
        self.run_every = run_every
        self.window = window

        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.alert_lock = threading.Lock()

        self.tailer = None
        self.workers = []

    def start(self):
        self.tailer = LogTailer(
            self.log_path, self.queue, self.stop_event,
            from_start=self.from_start,
        )
        self.workers = [
            DetectionWorker(
                i, self.queue, self.alert_sink, self.alert_lock,
                window=self.window, run_every=self.run_every,
            )
            for i in range(self.num_workers)
        ]
        for w in self.workers:
            w.start()
        self.tailer.start()

    def stop(self):
        """Signal the tailer to stop, drain the queue, and join all threads."""
        self.stop_event.set()
        if self.tailer:
            self.tailer.join(timeout=2.0)

        # Push one sentinel per worker so each unblocks and exits.
        for _ in self.workers:
            self.queue.put(_SHUTDOWN)
        for w in self.workers:
            w.join(timeout=2.0)

    def run_for(self, seconds):
        """Convenience: run the pipeline for a fixed duration, then stop."""
        self.start()
        try:
            time.sleep(seconds)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
