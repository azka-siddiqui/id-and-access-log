"""
correlation.py

This file implements event correlation to identify multi-step attack patterns.
For example, if an IP address performs a 'PORT_SCAN' and then quickly has a 
'LOGIN_FAILED' event within 2 minutes, we flag a correlated alert. This ensurs
detection of more advanced intrusions (as opposed to single-failed events). 
"""

from datetime import timedelta

def correlate_events(events: list) -> list:
    """
    Given a list of event dictionaries, look for suspicious event sequences
    that occur within a short timeframe. For instance:
      - 'PORT_SCAN' -> 'LOGIN_FAILED' within 2 minutes from the same IP address.

    Returns a list of alert messages describing each suspicious sequence found.
    """

    # Prepare a list to store correlation-based alerts
    alerts = []

    # Sort events by timestamp to process them in chronological order
    events_sorted = sorted(events, key=lambda x: x['timestamp'])

    # Iterate through events in pairs (e1, e2) to detect suspicious sequences
    for i in range(len(events_sorted) - 1):
        e1 = events_sorted[i]
        e2 = events_sorted[i + 1]

        # Check if both events come from the same IP address
        if e1['ip'] == e2['ip']:
            # Calculate the time difference between consecutive events
            time_diff = e2['timestamp'] - e1['timestamp']

            # If the time_diff is under 2 minutes, we check for specific patterns
            if time_diff < timedelta(minutes=2):
                # Example correlation rule: 'PORT_SCAN' -> 'LOGIN_FAILED'
                if e1['event'] == 'PORT_SCAN' and e2['event'] == 'LOGIN_FAILED':
                    alert_msg = (
                        f"Correlated Alert: IP={e1['ip']} had PORT_SCAN -> LOGIN_FAILED "
                        f"within {time_diff} at {e1['timestamp']}."
                    )
                    alerts.append(alert_msg)

    # Return all correlation-based alerts
    return alerts
