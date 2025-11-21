import requests

ABUSEIPDB_API_KEY = "39ecd07e36a24698b695e35f4a5d0a2b52b52a94cdf55588c57fedb7d82f6568485fb8b4fabe73db"  # <-- Replace with your key

def check_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90  # Check reports from last 90 days
    }
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    if "data" in data:
        return {
            "ip": data["data"].get("ipAddress"),
            "isWhitelisted": data["data"].get("isWhitelisted"),
            "abuseConfidenceScore": data["data"].get("abuseConfidenceScore"),
            "countryCode": data["data"].get("countryCode"),
            "totalReports": data["data"].get("totalReports"),
            "hostnames": data["data"].get("hostnames"),
            "usageType": data["data"].get("usageType"),
            "isp": data["data"].get("isp"),
            "domain": data["data"].get("domain"),
            "lastReportedAt": data["data"].get("lastReportedAt"),
            "categories": data["data"].get("categories"),
        }
    else:
        return {"error": data.get("errors", data)}

if __name__ == "__main__":
    test_ip = "185.220.101.1"  # Example: known Tor exit node
    result = check_abuseipdb(test_ip)
    from pprint import pprint
    pprint(result)
