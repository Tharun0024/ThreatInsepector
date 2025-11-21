def calculate_risk_score(
    abuse_score=0,
    blocklist_hit=False,
    tor_exit=False,
    vpn_detected=False,
    proxy_detected=False,
    port_activity=0,
    history_score=0,
    # Context Features: pass as needed
    asn_reputation=None,            # "good", "bad", "unknown"
    provider_category=None,         # "residential", "datacenter", "vpn", "hosting", etc.
    hour_of_day=None,               # int 0-23
    failed_logins=0,
    port_scan_count=0,
    traffic_spike=False,
    return_all_debug=False
):
    explanations = []
    score = abuse_score / 100.0
    debug_contributions = {
        "abuse_score": score,
        "blocklist": 0.1 if blocklist_hit else 0.0,
        "tor_exit": 0.3 if tor_exit else 0.0,
        "vpn": 0.25 if vpn_detected else 0.0,
        "proxy": 0.25 if proxy_detected else 0.0,
        "port_activity": min(port_activity / 200.0, 0.08),
        "history": min(history_score / 200.0, 0.08)
    }
    # Context Features (higher weights)
    debug_contributions["asn"] = 0.3 if asn_reputation == "bad" else 0.0
    debug_contributions["provider_category"] = 0.2 if provider_category in ("vpn", "hosting", "datacenter") else 0.0
    debug_contributions["off_hours"] = 0.05 if hour_of_day is not None and (hour_of_day < 6 or hour_of_day > 22) else 0.0
    debug_contributions["failed_logins"] = 0.05 if failed_logins >= 5 else 0.0
    debug_contributions["port_scan"] = 0.1 if port_scan_count >= 5 else 0.0
    debug_contributions["traffic_spike"] = 0.05 if traffic_spike else 0.0

    # Calculate final score
    for val in debug_contributions.values():
        score += val
    score = min(max(score, 0.0), 1.0)

    # Count signals for confidence (excluding abuse score)
    signal_count = sum([
        bool(blocklist_hit),
        bool(tor_exit),
        bool(vpn_detected),
        bool(proxy_detected),
        port_activity > 50,
        history_score > 30,
        (asn_reputation == "bad"),
        (provider_category in ("vpn", "hosting", "datacenter")),
        (hour_of_day is not None and (hour_of_day < 6 or hour_of_day > 22)),
        failed_logins >= 5,
        port_scan_count >= 5,
        bool(traffic_spike)
    ])
    if abuse_score >= 40:
        signal_count += 1

    # AI Confidence Tag
    if signal_count >= 4:
        confidence = "High"
    elif signal_count == 3:
        confidence = "Medium"
    elif signal_count == 2:
        confidence = "Low"
    else:
        confidence = "Very Low"

    # Context feature explanations
    if asn_reputation == "bad":
        explanations.append("ASN is in known bad-reputation or blacklisted ranges.")
    elif asn_reputation == "good":
        explanations.append("ASN is recognized as reputable.")

    if provider_category in ("vpn", "hosting", "datacenter"):
        explanations.append(f"Provider in category: {provider_category} (increases risk).")

    if hour_of_day is not None and (hour_of_day < 6 or hour_of_day > 22):
        explanations.append("Activity during atypical hours (possible risk).")

    if failed_logins >= 5:
        explanations.append(f"{failed_logins} failed login attempts observed.")

    if port_scan_count >= 5:
        explanations.append(f"Port scan patterns detected ({port_scan_count} targets).")

    if traffic_spike:
        explanations.append("Anomalous traffic spike detected.")

    # Standard enrichment explanations
    explanations.append("This IP is listed as a TOR exit node." if tor_exit else "No evidence this IP is a TOR exit node.")
    explanations.append("VPN usage or infrastructure detected for this IP." if vpn_detected else "No VPN activity or infrastructure detected.")
    explanations.append("Flagged as open proxy or proxy-related service." if proxy_detected else "No proxy service or history found for this IP.")
    explanations.append("This IP appears on a known threat blocklist." if blocklist_hit else "IP is not found on public threat blocklists.")

    # Abuse score
    if abuse_score >= 80:
        explanations.append(f"High AbuseIPDB score ({abuse_score}): severe and recent abuse activity reported.")
    elif abuse_score >= 40:
        explanations.append(f"Moderate AbuseIPDB score ({abuse_score}): some questionable behavior reported.")
    else:
        explanations.append("No significant abuse or threat activity on AbuseIPDB.")

    explanations.append("Unusual or risky port activity detected." if port_activity > 50 else "No suspicious or risky port activity noted.")
    explanations.append("This IP or source has a history of suspicious or risky activity." if history_score > 30 else "Clean activity history: no risky prior behaviors identified.")

    # Option A: More realistic thresholds
    if score >= 0.65:
        level = "High"
    elif score >= 0.25:
        level = "Medium"
    else:
        level = "Low"

    result = {
        "level": level,
        "score": round(score, 3),
        "confidence": confidence,
        "factors": explanations
    }
    if return_all_debug:
        result["raw_scores"] = debug_contributions
        result["total"] = score
        result["signal_count"] = signal_count
    return result
