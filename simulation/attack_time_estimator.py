def estimate_attack_time(vulnerabilities):

    try:
        # ✅ Safe default
        vulnerabilities = vulnerabilities or []

        times = {}

        # Normalize safely
        vuln_list = []
        for v in vulnerabilities:
            try:
                vuln_list.append(str(v).lower())
            except:
                continue

        # =============================
        # ⏱ Attack time logic
        # =============================

        # XSS
        if any("content security policy" in v or "xss" in v for v in vuln_list):
            times["XSS Exploit"] = "2 - 4 mins"

        # Clickjacking
        if any("frame" in v for v in vuln_list):
            times["Clickjacking Exploit"] = "3 - 5 mins"

        # SSL Strip
        if any("hsts" in v for v in vuln_list):
            times["SSL Strip Attack"] = "4 - 6 mins"

        # Session Hijacking
        if any("xss" in v for v in vuln_list):
            times["Session Hijacking"] = "5 - 8 mins"

        # SQL Injection
        if any("sql" in v for v in vuln_list):
            times["SQL Injection Attack"] = "3 - 6 mins"

        # =============================
        # 🧠 Fallback
        # =============================
        if not times:
            times["Generic Attack"] = "5 - 10 mins"

        return times

    except Exception as e:
        print("Attack Time Error:", e)
        return {"Error": "Estimation failed"}