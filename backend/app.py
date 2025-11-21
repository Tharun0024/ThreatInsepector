from fastapi import FastAPI, UploadFile, File, Form, Body
from fastapi.middleware.cors import CORSMiddleware
import os
import datetime

from core.geoip import lookup_ip
from core.tor_collector import fetch_tor_exit_ips
from core.log_parser import parse_log_file
from core.risk_engine import calculate_risk_score
from core.ipcheck import check_abuseipdb
from core.fileupload import parse_log_file
from core.analyze_all import batch_analyze  # <-- Batch analyzer

TOR_EXIT_IPS = fetch_tor_exit_ips()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_port_activity(port):
    safe_ports = [80, 443, 53]
    risky_ports = [23, 3389, 445, 21]
    try:
        p = int(port)
        if p in safe_ports:
            return 0
        elif p in risky_ports:
            return 80
        else:
            return 0
    except:
        return 0

def get_history_score(ip, isp_data):
    trusted_isps = ["Google", "Cloudflare", "Airtel"]
    provider = isp_data.get("provider", "")
    if any(t.lower() in provider.lower() for t in trusted_isps):
        return 0
    else:
        return 0

@app.post("/analyze")
async def analyze_ip(
    ip: str = Form(...),
    protocol: str = Form(...),
    country: str = Form(...),
    port: str = Form(None),
    timestamp: str = Form(None),
    response_time_ms: float = Form(0.0),
    traffic_volume_kb: float = Form(0.0),
    matched_with_guard: int = Form(0),
    incident_type: str = Form(None)
):
    # Timestamp processing
    if timestamp:
        try:
            ts_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        except:
            ts_obj = datetime.datetime.now()
    else:
        ts_obj = datetime.datetime.now()
    hour = ts_obj.hour
    weekday = ts_obj.weekday()

    # AbuseIPDB enrichment
    abuseipdb_result = check_abuseipdb(ip)
    abuse_score = abuseipdb_result.get("abuseConfidenceScore", 0)

    # Lookup and threat enrichment
    geo_data, isp_data = lookup_ip(ip)
    is_tor = ip in TOR_EXIT_IPS or int(matched_with_guard) == 1

    vpn_detected = False
    proxy_detected = False

    # Supplement with heuristics from enrichment data
    domain = abuseipdb_result.get("domain", "") or ""
    hostnames = abuseipdb_result.get("hostnames", [])
    # naive VPN/proxy detection
    if any("vpn" in str(domain).lower() or "vpn" in str(h).lower() for h in ([domain] + hostnames)):
        vpn_detected = True
    if any("proxy" in str(domain).lower() or "proxy" in str(h).lower() for h in ([domain] + hostnames)):
        proxy_detected = True

    blocklist_hit = abuse_score >= 70
    port_activity = get_port_activity(port)
    history_score = get_history_score(ip, isp_data)

    # Calculate risk engine score and level
    risk_result = calculate_risk_score(
        abuse_score=abuse_score,
        blocklist_hit=blocklist_hit,
        tor_exit=is_tor,
        vpn_detected=vpn_detected,
        proxy_detected=proxy_detected,
        port_activity=port_activity,
        history_score=history_score
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
        {"label": "Geolocation", "value": 20 if geo_data.get('country', '') != "Unknown" else 0},
        {"label": "Port Activity", "value": port_activity},
        {"label": "History", "value": history_score},
    ]

    return {
        "ip": ip,
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
            "risk_engine_score": float(risk_score)
        }
    }

@app.post("/upload_logs")
async def upload_logs(file: UploadFile = File(...)):
    os.makedirs("uploads", exist_ok=True)
    filepath = os.path.join("uploads", file.filename)
    with open(filepath, "wb") as f:
        f.write(await file.read())
    ip_entries = parse_log_file(filepath)
    return {
        "status": "success",
        "filename": file.filename,
        "extracted_ips": ip_entries,
    }

@app.post("/analyze_batch")
async def analyze_batch_api(payload: dict = Body(...)):
    ip_entries = payload.get("ip_entries", [])
    results = batch_analyze(ip_entries)
    return {"results": results}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
