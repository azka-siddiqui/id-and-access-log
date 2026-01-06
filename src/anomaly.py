"""
anomaly.py

This file implements threshold-based anomaly detection. It checks for scenarios
where the same IP address has triggered too many "LOGIN_FAILED" events within a short
time window (e.g., 5 minutes). If an IP surpasses the threshold, we flag it as suspicious.

"""

from datetime import timedelta

def detect_threshold_anomalies(events: list, fail_event="LOGIN_FAILED",
                               threshold=3, window_minutes=5) -> list:      # lowered threshold to 3
    """
    Given a list of event dictionaries, detect if an IP exceeds the 'threshold'
    number of 'fail_event' occurrences within 'window_minutes'. Each occurrence
    that violates this rule will produce an alert message (string).
    """

    # List for storing alert messages
    alerts = []

    # Dictionary that maps each IP to its list of events
    ip_events_map = {}

    # Group all events by IP
    for e in events:
        ip = e.get('ip')
        ip_events_map.setdefault(ip, []).append(e)

    # Process each IP separately
    for ip, ip_events in ip_events_map.items():
        # Filter out events that match our 'fail_event' (by default, "LOGIN_FAILED")
        fail_events = [evt for evt in ip_events if evt['event'] == fail_event]
        
        # Sort fail events by timestamp to process them in chronological order
        fail_events.sort(key=lambda x: x['timestamp'])

        # Check how many fail events occurred within the specified time window
        for i, current_fail in enumerate(fail_events):
            current_time = current_fail['timestamp']
            
            # Define the start of the time window
            window_start = current_time - timedelta(minutes=window_minutes)

            # Count how many fail_events happened between window_start and current_time
            count_recent = sum(
                1 for fe in fail_events
                if window_start <= fe['timestamp'] <= current_time
            )

            # If the count exceeds the threshold, we flag an alert
            if count_recent > threshold:
                alert_msg = (
                    f"Suspicious activity from IP={ip}: "
                    f"{count_recent} '{fail_event}' events in the last {window_minutes} minutes "
                    f"ending at {current_time}."
                )
                alerts.append(alert_msg)

    # Return all accumulated alert messages (strings that define the anomaly)
    return alerts
