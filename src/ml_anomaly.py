"""
ml_anomaly.py

Demonstrates how to incorporate a simple ML-based anomaly detection approach
(Isolation Forest) into the existing log analysis pipeline. 

Note: currently this file isn't connected to anything

"""

import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta

class MLAnomalyDetector:
    """
    A tiny wrapper around IsolationForest to handle training and prediction
    for log-based anomaly detection. 
    """

    def __init__(self, random_state=42):
        self.model = IsolationForest(random_state=random_state)
        self.is_trained = False

    def fit(self, feature_matrix: np.ndarray):
        """
        Train the IsolationForest model on a 2D feature matrix of shape (num_samples, num_features).
        We assume the data is mostly 'normal' (few anomalies) for it to learn typical behavior.
        """
        self.model.fit(feature_matrix)
        self.is_trained = True

    def predict(self, feature_matrix: np.ndarray):
        """
        Returns a list of predictions (1 for normal, -1 for anomaly).
        If you want an anomaly score, you can also call self.model.score_samples(...)
        """
        if not self.is_trained:
            raise ValueError("Model is not trained. Call fit() before predict().")
        return self.model.predict(feature_matrix)

# -------------------------------------------------------------------------
# Feature extraction helper functions
# -------------------------------------------------------------------------

def build_features_for_ip(events: list) -> np.ndarray:
    """
    Example 'feature extraction' function. This is *very simplistic*. 
    We group events by IP, then for each IP, we compute a few numeric features:
      1) total number of events
      2) number of 'LOGIN_FAILED' events
      3) ratio of LOGIN_FAILED to total events
      4) time since first event (in minutes)
      5) time since last event (in minutes)
    
    Returns a 2D numpy array (one row per IP, columns = these features).
    """
    
    # Group by IP
    ip_events_map = {}
    for e in events:
        ip = e['ip']
        ip_events_map.setdefault(ip, []).append(e)

    feature_rows = []
    for ip, ip_events in ip_events_map.items():
        # Sort by timestamp
        ip_events.sort(key=lambda x: x['timestamp'])

        total_events = len(ip_events)
        fail_events = sum(1 for evt in ip_events if evt['event'] == 'LOGIN_FAILED')
        fail_ratio = fail_events / total_events if total_events > 0 else 0.0

        # Time-based features
        first_time = ip_events[0]['timestamp']
        last_time = ip_events[-1]['timestamp']
        now = datetime.now()

        # Example approach: measure how long ago the first and last events occurred from "now"
        # If logs are old, you might want to use the difference between first and last instead
        time_since_first = (now - first_time).total_seconds() / 60.0
        time_since_last = (now - last_time).total_seconds() / 60.0

        # Build the feature row
        row = [total_events, fail_events, fail_ratio, time_since_first, time_since_last]
        feature_rows.append(row)

    # Convert to numpy array
    return np.array(feature_rows)
