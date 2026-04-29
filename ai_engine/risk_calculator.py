# CVSS v3.1 simplified scoring + OWASP-style mapping

CVSS_BASE = {
    "AV": {"N": 0.85},           # Network
    "AC": {"L": 0.77},           # Low
    "PR": {"N": 0.85},           # None
    "UI": {"N": 0.85},           # None
    "S":  {"U": 6.42},           # Scope Unchanged base multiplier
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

# Map findings → CVSS impact (C/I/A) and label
VULN_MAP = {
    "sql":  {"label": "SQL Injection",            "C": "H", "I": "H", "A": "H"},
    "rce":  {"label": "Remote Code Execution",    "C": "H", "I": "H", "A": "H"},
    "xss":  {"label": "Cross-Site Scripting",     "C": "L", "I": "L", "A": "N"},
    "csrf": {"label": "CSRF",                     "C": "L", "I": "L", "A": "N"},
    "hsts": {"label": "HSTS Missing",             "C": "L", "I": "N", "A": "N"},
    "frame":{"label": "Clickjacking",             "C": "L", "I": "L", "A": "N"},
    "header":{"label": "Security Headers Missing","C": "N", "I": "N", "A": "N"},
}

# Ports → exposure risk (treated as availability/integrity surface)
PORT_RISK = {
    21: ("FTP",  "L","L","L"),
    22: ("SSH",  "L","L","N"),
    23: ("Telnet","H","H","H"),
    80: ("HTTP", "L","N","N"),
    443:("HTTPS","N","N","N"),
    3306:("MySQL","H","H","H"),
    3389:("RDP", "H","H","H"),
}

def _cvss_score(C, I, A):
    # Base score (simplified, deterministic)
    impact = 1 - (1 - CVSS_BASE["C"][C]) * (1 - CVSS_BASE["I"][I]) * (1 - CVSS_BASE["A"][A])
    exploitability = CVSS_BASE["AV"]["N"] * CVSS_BASE["AC"]["L"] * CVSS_BASE["PR"]["N"] * CVSS_BASE["UI"]["N"]
    score = (impact * CVSS_BASE["S"]["U"]) + (exploitability * 8.22)
    return round(min(score, 10.0), 1)

def calculate_risk_score(vulnerabilities, open_ports, admin_panels):
    try:
        vulns = [str(v).lower() for v in (vulnerabilities or [])]
        ports = []
        for p in (open_ports or []):
            try:
                ports.append(int(str(p).split()[0]))
            except:
                continue

        findings = []
        scores = []

        # ---- Vulnerabilities → CVSS
        for v in vulns:
            matched = False
            for key, meta in VULN_MAP.items():
                if key in v:
                    s = _cvss_score(meta["C"], meta["I"], meta["A"])
                    findings.append({"type": meta["label"], "cvss": s})
                    scores.append(s)
                    matched = True
                    break
            if not matched:
                s = _cvss_score("L","L","N")
                findings.append({"type": "Generic Misconfiguration", "cvss": s})
                scores.append(s)

        # ---- Ports → CVSS-like exposure
        for p in ports:
            name, C, I, A = PORT_RISK.get(p, ("Other", "L","N","N"))
            s = _cvss_score(C, I, A)
            findings.append({"type": f"Open Port {p} ({name})", "cvss": s})
            scores.append(s)

        # ---- Admin panels → exposure boost
        admin_count = len(admin_panels or [])
        if admin_count:
            # treat as integrity/confidentiality exposure
            s = _cvss_score("H","H","N")
            findings.append({"type": f"Admin Exposure x{admin_count}", "cvss": s})
            scores.append(s)

        # ---- Final aggregation (deterministic)
        overall = round(sum(scores)/len(scores), 1) if scores else 0.0

        if overall < 3:
            level = "LOW"
        elif overall < 6:
            level = "MEDIUM"
        elif overall < 8:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return overall, level, findings

    except Exception as e:
        print("Risk Error:", e)
        return 0.0, "LOW", []