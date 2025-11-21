from datetime import datetime as dt, timedelta


def parse_timestamp(ts):
    """
    Attempts to parse a timestamp in known formats.
    You can add more formats as needed.
    """
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return dt.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unsupported timestamp format: {ts}")


def is_within_time_window(event_time, node_time, window_seconds=300):
    diff = abs((event_time - node_time).total_seconds())
    return diff <= window_seconds


def correlate_logs_with_nodes(log_events, node_events, window_seconds=300):
    """
    Returns list of (log, node) pairs that match on IP and within the time window.
    """
    correlated = []
    for log in log_events:
        log_time = parse_timestamp(log['timestamp'])
        for node in node_events:
            node_time = parse_timestamp(node['timestamp'])
            if is_within_time_window(log_time, node_time, window_seconds) and log['ip'] == node['ip']:
                correlated.append((log, node))
    return correlated
