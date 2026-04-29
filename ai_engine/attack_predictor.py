def predict_attack(vulnerabilities):

    try:
        # ✅ Safe default
        vulnerabilities = vulnerabilities or []

        predictions = {}

        # Normalize
        vuln_list = []
        for v in vulnerabilities:
            try:
                vuln_list.append(str(v).lower())
            except:
                continue

        # =============================
        # 🔮 Prediction logic
        # =============================

        if any("content security policy" in v for v in vuln_list):
            predictions["Cross Site Scripting (XSS)"] = "70%"

        if any("x-frame-options" in v for v in vuln_list):
            predictions["Clickjacking Attack"] = "60%"

        if any("hsts" in v for v in vuln_list):
            predictions["SSL Strip Attack"] = "50%"

        if any("xss" in v for v in vuln_list):
            predictions["Session Hijacking"] = "65%"

        if any("sql" in v for v in vuln_list):
            predictions["SQL Injection Exploit"] = "80%"

        # =============================
        # 🧠 Smart fallback
        # =============================
        if not predictions:
            predictions["Low Risk Attack Probability"] = "20%"

        return predictions

    except Exception as e:
        print("Attack Predictor Error:", e)
        return {"Error": "Prediction failed"}