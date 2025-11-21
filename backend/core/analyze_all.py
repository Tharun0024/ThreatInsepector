from core.geoip import lookup_ip
from core.tor_collector import fetch_tor_exit_ips
from core.risk_engine import calculate_risk_score
from core.ipcheck import check_abuseipdb
import datetime

TOR_EXIT_IPS = fetch_tor_exit_ips()


def batch_analyze(ip_entries):
    results = []
    for entry in ip_entries:
        ip = entry.get("ip") or ""
        port = entry.get("port") or ""
        timestamp = entry.get("timestamp") or ""
        incident_type = entry.get("incidentType") or ""

        # Timestamp logic (same as /analyze)
        if timestamp:
            try:
                ts_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except:
                ts_obj = datetime.datetime.now()
        else:
            ts_obj = datetime.datetime.now()
        hour = ts_obj.hour

        abuseipdb_result = check_abuseipdb(ip)
        abuse_score = abuseipdb_result.get("abuseConfidenceScore", 0)
        geo_data, isp_data = lookup_ip(ip)
        is_tor = ip in TOR_EXIT_IPS
        vpn_detected = False
        proxy_detected = False
        domain = abuseipdb_result.get("domain", "") or ""
        hostnames = abuseipdb_result.get("hostnames", [])
        if any("vpn" in str(domain).lower() or "vpn" in str(h).lower() for h in ([domain] + hostnames)):
            vpn_detected = True
        if any("proxy" in str(domain).lower() or "proxy" in str(h).lower() for h in ([domain] + hostnames)):
            proxy_detected = True

        blocklist_hit = abuse_score >= 70
        port_activity = 0  # You can re-use your get_port_activity here
        history_score = 0  # You can re-use your get_history_score here

        risk_result = calculate_risk_score(
            abuse_score=abuse_score,
            blocklist_hit=blocklist_hit,
            tor_exit=is_tor,
            vpn_detected=vpn_detected,
            proxy_detected=proxy_detected,
            port_activity=port_activity,
            history_score=history_score,
        )
        risk_level = risk_result["level"]
        risk_score = risk_result["score"]
        risk_distribution = {
            "Low": int(risk_level == "Low"),
            "Medium": int(risk_level == "Medium"),
            "High": int(risk_level == "High"),
        }
        factor_scores = [
            {"label": "AbuseIPDB Score", "value": abuse_score},
            {"label": "TOR", "value": int(is_tor) * 80},
            {"label": "VPN", "value": int(vpn_detected) * 80},
            {"label": "Proxy", "value": int(proxy_detected) * 80},
            {"label": "Blocklists", "value": 40 if blocklist_hit else 0},
            {"label": "Geolocation", "value": 20 if geo_data.get("country", "") != "Unknown" else 0},
            {"label": "Port Activity", "value": port_activity},
            {"label": "History", "value": history_score},
        ]
        results.append({
            "ip": ip,
            "port": port,
            "timestamp": timestamp,
            "incident_type": incident_type,
            "risk_level": risk_level,
            "classification": {
                "TOR": bool(is_tor),
                "VPN": bool(vpn_detected),
                "Proxy": bool(proxy_detected),
            },
            "geolocation": geo_data,
            "isp": isp_data,
            "factor_scores": factor_scores,
            "risk_distribution": risk_distribution,
            "notes": "Risk computed using threat enrichment and AbuseIPDB (ML is disabled).",
            "risk_explanation": risk_result.get("factors", []),
            "scores": {
                "abuse_score": float(abuse_score),
                "risk_engine_score": float(risk_score),
            }
        })
    return results
