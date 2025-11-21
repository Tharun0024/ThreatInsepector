import re
from typing import List, Dict

LOG_REGEX = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<incidentType>[A-Z]+).*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<port>\d+))?"
)

def parse_log_file(filepath: str) -> List[Dict[str, str]]:
    ip_entries = []
    seen = set()
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = LOG_REGEX.search(line)
            if match:
                ip = match.group("ip")
                port = match.group("port") or ""
                timestamp = match.group("timestamp")
                incidentType = match.group("incidentType")
                key = (ip, port, timestamp, incidentType)
                if key not in seen:
                    ip_entries.append({
                        "ip": ip,
                        "port": port,
                        "timestamp": timestamp,
                        "incidentType": incidentType,
                    })
                    seen.add(key)
    return ip_entries
