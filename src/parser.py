"""
parser.py

This file is responsible for taking raw log lines (strings) and converting them
into structured Python dictionaries with fields like timestamp, IP address, event,
and user. It uses regular expressions to extract the data and ensures the timestamp
is converted into a datetime object for easier time-based comparisons later.
"""

import re
from datetime import datetime

def parse_log_line(line: str) -> dict:
    """
    Takes a single string representing a log line and returns a dict with keys:
      'timestamp' (datetime object),
      'ip' (string),
      'event' (string),
      'user' (string).
    Returns None if the line doesn't match the expected format.
    """

    # Regular expression pattern specifying the expected log format:
    # "YYYY-MM-DD HH:MM:SS, IP=xxx.xxx.xxx.xxx, EVENT=..., USER=..."
    pattern = (
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), '
        r'IP=(?P<ip>[\d\.]+), '
        r'EVENT=(?P<event>[A-Z_]+), '
        r'USER=(?P<user>\w+)'
    )

    # Use re.search to match the line against our pattern
    match = re.search(pattern, line)
    if match:
        # match.groupdict() creates a dictionary of named groups from the regex
        data = match.groupdict()

        # Convert the timestamp string to a datetime object
        data['timestamp'] = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')

        # Return the parsed data as a dictionary
        return data
    else:
        # If the log line doesn't match our pattern, we return None
        return None
