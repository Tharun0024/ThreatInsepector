import re

# Matches IPv4 addresses
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
# Matches timestamps in common formats (adjust regex for your log style)
timestamp_pattern = r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'

def extract_ips_and_metadata(log_text):
    ips = re.findall(ip_pattern, log_text)
    # Find all timestamps in the log text (paired or used as needed)
    timestamps = re.findall(timestamp_pattern, log_text)
    # For full enrichment, each IP/timestamp pair needs matching logic.

    # Return list of dicts for further enrichment.
    results = []
    for ip in ips:
        # Optionally associate first found timestamp (improve logic for real logs!)
        ts = timestamps[0] if timestamps else None
        results.append({"ip": ip, "timestamp": ts})
    return results

def parse_log_file(filepath):
    with open(filepath, 'r') as f:
        text = f.read()
    return extract_ips_and_metadata(text)
