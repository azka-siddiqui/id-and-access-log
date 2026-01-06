"""
main.py

The main entry point of the Security Log Analysis & Intrusion Detection system. 
This file reads raw log lines from a sample.log, uses 'parse.py' to 
convert them into structured data, and periodically runs both threshold-based anomaly 
detection (from 'anomaly.py')and event correlation checks. 
Any suspicious findings get written to an output file.

"""

import os
from parser import parse_log_line        # <-- Updated import from 'parse.py'
from anomaly import detect_threshold_anomalies
from correlation import correlate_events

def main():
    """
    The primary execution function:
      1. Define where to read logs and where to write alerts.
      2. Parse each log line into a structured dictionary.
      3. Periodically run detection (both anomaly & correlation).
      4. Write suspicious events to an output file.
    """

    # Paths to the input log file and the output file
    LOG_FILE = os.path.join("logs", "sample.log")
    OUTPUT_FILE = os.path.join("output", "suspicious_events.txt")

    # If an output file already exists, remove it to start fresh
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    # Store all parsed events in this list
    parsed_events = []
    #print(parsed_events)            # debugging check

    # Read the log file line by line
    with open(LOG_FILE, "r") as log_f:
        for line in log_f:
            # Parse each line using our custom parser (now in parse.py)
            event_data = parse_log_line(line)
            if event_data:
                parsed_events.append(event_data)

            # Every 10 events, we run our detection logic
            if len(parsed_events) % 10 == 0:
                # 1. Run threshold anomaly detection
                anomaly_alerts = detect_threshold_anomalies(parsed_events)

                # 2. Run event correlation checks
                correlation_alerts = correlate_events(parsed_events)

                # Combine all alerts into a single list
                all_alerts = anomaly_alerts + correlation_alerts

                # Append suspicious alerts into output file
                if all_alerts:
                    with open(OUTPUT_FILE, "a") as out_f:
                        for alert in all_alerts:
                            out_f.write(alert + "\n")

    # Print when process is complete
    print(f"Done processing logs. Check '{OUTPUT_FILE}' for alerts.")
    # print(OUTPUT_FILE.encode("utf-8"))            # debugging

# Standard Python entry point
if __name__ == "__main__":
    main()
