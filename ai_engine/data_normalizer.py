# ai_engine/data_normalizer.py

def normalize_scan_data(scan_results):
    normalized = []

    # URL vulnerabilities
    for v in scan_results.get("vulns", []):
        normalized.append({
            "name": v.get("issue", "Unknown"),
            "port": 80,
            "severity": v.get("severity", 5),
            "evidence": True,
            "port_open": True,
            "response_valid": True
        })

    # Ports
    for p in scan_results.get("ports", []):
        normalized.append({
            "name": f"Open Port {p}",
            "port": p,
            "severity": 4,
            "evidence": True,
            "port_open": True,
            "response_valid": True
        })

    # Admin panels
    for a in scan_results.get("admin", []):
        normalized.append({
            "name": "Exposed Admin Panel",
            "port": 80,
            "severity": 8,
            "evidence": True,
            "port_open": True,
            "response_valid": True
        })

    return normalized