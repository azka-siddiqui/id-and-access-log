# Security Log Analysis & Intrusion Detection

## Overview

This project implements a lightweight **security log analysis and intrusion detection system** that ingests raw system and network logs, detects suspicious behavior using rule-based and machine learning techniques, and outputs actionable alerts for review.

The system is designed to simulate core concepts used in SIEM and IDS tools, including log parsing, threshold-based anomaly detection, event correlation, and ML-based anomaly detection.

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

---

## Project Structure

```text
.
├── logs/
│   └── Raw log files
│
├── output/
│   └── Generated alert files
│
├── src/
│   ├── log_parser.py        # Regex-based log parsing
│   ├── threshold_rules.py  # Threshold-based anomaly detection
│   ├── correlation.py      # Event correlation logic
│   ├── isolation_forest.py # ML-based anomaly detection
│   └── main.py             # End-to-end pipeline orchestration
│
└── README.md
