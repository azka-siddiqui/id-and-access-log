# Security Log Analysis & Intrusion Detection

## Overview

This project implements a lightweight **security log analysis and intrusion detection system** that ingests raw system and network logs, detects suspicious behavior using rule-based and machine learning techniques, and outputs actionable alerts for review.

It can run in two modes: a single-pass **batch** mode over an existing log file, and a **multithreaded real-time** mode that follows a log as it grows (like `tail -f`) and runs detection concurrently on a rolling time window.

The system is designed to simulate core concepts used in SIEM and IDS tools, including log parsing, threshold-based anomaly detection, event correlation, ML-based anomaly detection, and real-time streaming ingestion.

---

## Key Capabilities

- **Structured Log Parsing**
  - Converts raw log lines into structured Python dictionaries using regular expressions.
  - Normalizes fields such as timestamp, IP address, event type, and status.

- **Threshold-Based Anomaly Detection**
  - Detects excessive failed login attempts from a single IP within a configurable time window.
  - Useful for identifying brute-force authentication attacks.

- **Event Correlation**
  - Identifies suspicious multi-step attack patterns.
  - Example: a `PORT_SCAN` event quickly followed by multiple `LOGIN_FAILED` events from the same IP.

- **Machine Learning–Based Detection**
  - Uses an **Isolation Forest** model to identify anomalous behavior patterns.
  - Complements rule-based detection by capturing previously unseen anomalies.

- **Alert Generation**
  - All detected suspicious activity is written to a dedicated output file for further investigation.

- **Multithreaded Real-Time Ingestion**
  - A producer thread follows the log file as it grows and pushes new lines onto a thread-safe `queue.Queue`.
  - A pool of consumer (worker) threads parse events and run detection concurrently on a rolling time window.
  - A shared, lock-guarded dedupe set ensures each alert is reported once regardless of which worker detects it, and a `threading.Event` coordinates clean shutdown.

---

## Usage

Run from the `src/` directory.

**Batch mode** (single pass over an existing log file):

```bash
python main.py --mode batch --log ../logs/sample.log
```

**Real-time mode** (follow a live log with multiple worker threads). In one terminal, stream synthetic events:

```bash
python log_generator.py ../logs/live.log 20
```

In another terminal, follow that log and detect intrusions as they happen:

```bash
python main.py --mode realtime --log ../logs/live.log --workers 3 --seconds 20
```

Detected alerts print to the console (tagged with the worker that found them) and are appended to `output/suspicious_events.txt`.

---

## Project Structure

```text
.
├── logs/
│   └── sample.log
│       # Raw security log file containing events such as LOGIN_FAILED and PORT_SCAN
│
├── output/
│   └── suspicious_events.txt
│       # Generated alerts from anomaly detection and event correlation
│
├── src/
│   ├── main.py
│   │   # Main entry point for the system.
│   │   # Supports batch mode (single pass) and multithreaded realtime mode.
│   │
│   ├── ingest.py
│   │   # Multithreaded real-time ingestion pipeline.
│   │   # LogTailer (producer) follows the log and enqueues lines; DetectionWorker
│   │   # threads (consumers) parse events and run detection on a rolling window.
│   │
│   ├── log_generator.py
│   │   # Demo helper that streams synthetic log events to a file so realtime
│   │   # mode has something live to follow.
│   │
│   ├── parser.py
│   │   # Regex-based log parser.
│   │   # Converts raw log lines into structured dictionaries with timestamp, IP address, event type, and user fields.
│   │
│   ├── anomaly.py
│   │   # Implements threshold-based anomaly detection.
│   │   # Flags IP addresses that exceed a configurable number of LOGIN_FAILED events within a defined time window.
│   │
│   ├── correlation.py
│   │   # Implements event correlation logic.
│   │   # Detects suspicious multi-step attack patterns such as PORT_SCAN followed by LOGIN_FAILED within a short timeframe.
│   │
│   ├── ml_anomaly.py
│   │   # ML-based anomaly detection using Isolation Forest.
│   │   # Includes feature extraction and model training/prediction logic.
│
└── README.md
