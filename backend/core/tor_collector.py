import requests
import time

def fetch_tor_exit_ips(cache_file=None, cache_time=3600):
    """
    Fetches TOR exit IPs from Onionoo.
    Optionally caches results in a local file for cache_time seconds.
    """
    # Use local cache if available and recent
    if cache_file and os.path.exists(cache_file):
        mtime = os.path.getmtime(cache_file)
        if time.time() - mtime < cache_time:
            try:
                with open(cache_file, 'r') as f:
                    return set(line.strip() for line in f)
            except Exception as e:
                print(f"Cache read error: {e}")

    url = "https://onionoo.torproject.org/details?flag=Exit"
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        relays = data.get("relays", [])
        ips = set()
        for relay in relays:
            for addr in relay.get("or_addresses", []):
                ip = addr.split(":")[0]
                # Only add IPv4 addresses
                if "." in ip:
                    ips.add(ip)
        # Optionally cache
        if cache_file:
            try:
                with open(cache_file, 'w') as f:
                    for ip in ips:
                        f.write(f"{ip}\n")
            except Exception as e:
                print(f"Cache write error: {e}")
        return ips
    except Exception as e:
        print(f"Error fetching TOR exit IPs: {e}")
        return set()
