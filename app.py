from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import requests
import time

from scanner.port_scanner import scan_ports
from scanner.admin_finder import find_admin_panels

from ai_engine.attack_predictor import predict_attack
from ai_engine.recommender import generate_recommendations
from simulation.attack_time_estimator import estimate_attack_time

app = Flask(__name__)

# ================= CACHE =================
scan_cache = {}
CACHE_TIME = 300  # 5 minutes

# ================= URL CLEAN =================
def clean_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

# ================= RISK ENGINE =================
def calculate_risk_score(vulns, ports, admin_panels):

    score = 0

    # Vulnerabilities
    for v in vulns:
        v = v.lower()

        if "sql" in v:
            score += 25
        elif "xss" in v:
            score += 15
        elif "clickjacking" in v:
            score += 10
        elif "hsts" in v:
            score += 8
        else:
            score += 5

    # Ports
    for p in ports:
        if str(p) in ["21", "22", "23", "3389"]:
            score += 10
        else:
            score += 3

    # Admin panels
    score += len(admin_panels) * 8

    score = min(score, 100)

    # Severity classification
    if score < 30:
        level = "LOW"
    elif score < 60:
        level = "MEDIUM"
    elif score < 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level

# ================= ATTACK PATHS =================
def generate_dynamic_paths(vulns, ports, admin):

    paths = []

    for v in vulns:
        v = v.lower()

        if "xss" in v:
            paths.append([
                "Inject payload",
                "Steal cookies",
                "Hijack session"
            ])

        if "sql" in v:
            paths.append([
                "Inject SQL query",
                "Dump database",
                "Access sensitive data"
            ])

    if any(str(p) == "22" for p in ports):
        paths.append([
            "Target SSH",
            "Brute force",
            "Access server"
        ])

    if len(admin) >= 2:
        paths.append([
            "Find exposed panels",
            "Try default creds",
            "Gain admin access"
        ])

    return paths

# ================= RECOMMENDATIONS =================
def generate_smart_recommendations(vulns, ports, admin):

    rec = []

    for v in vulns:
        v = v.lower()

        if "xss" in v:
            rec.append("Implement input validation and output encoding (prevent XSS)")

        if "clickjacking" in v:
            rec.append("Add X-Frame-Options or CSP frame-ancestors")

        if "hsts" in v:
            rec.append("Enable HSTS with strong max-age")

        if "server" in v:
            rec.append("Hide server headers")

    if any(str(p) == "22" for p in ports):
        rec.append("Disable SSH password login or restrict via firewall")

    if len(admin) > 0:
        rec.append("Protect admin panels with strong authentication")

    return list(set(rec))

# ================= BASIC SCAN =================
def scan_url(url):

    vulnerabilities = []

    try:
        r = requests.get(url, timeout=5)
        h = r.headers

        if "Content-Security-Policy" not in h:
            vulnerabilities.append("Missing CSP")

        if "X-Frame-Options" not in h:
            vulnerabilities.append("Clickjacking Risk")

        if "Strict-Transport-Security" not in h:
            vulnerabilities.append("HSTS Not Enabled")

        if "X-XSS-Protection" not in h:
            vulnerabilities.append("XSS Risk")

        if "Server" in h:
            vulnerabilities.append("Server Header Exposed")

    except:
        pass

    return list(set(vulnerabilities))

# ================= PARALLEL SCAN =================
def parallel_scan(url, domain):

    with ThreadPoolExecutor() as ex:
        v = ex.submit(scan_url, url)
        p = ex.submit(scan_ports, domain)
        a = ex.submit(find_admin_panels, url)

        return v.result(), p.result(), a.result()

# ================= AI ENGINE =================
def parallel_ai(v, p, a):

    with ThreadPoolExecutor() as ex:
        pred = ex.submit(predict_attack, v)
        attack_time = ex.submit(estimate_attack_time, v)
        paths = ex.submit(generate_dynamic_paths, v, p, a)
        risk = ex.submit(calculate_risk_score, v, p, a)
        rec = ex.submit(generate_smart_recommendations, v, p, a)

        risk_score, risk_level = risk.result()

    return {
        "attack_prediction": pred.result() or {},
        "attack_time": attack_time.result() or {},
        "attack_paths": paths.result() or [],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommendations": rec.result() or ["System appears relatively secure"]
    }

# ================= ROUTES =================
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/api/scan', methods=['POST'])
def api_scan():
    try:
        url = request.json.get("url")

        if not url:
            return jsonify({"success": False, "error": "Invalid URL"})

        now = time.time()

        # 🔥 CACHE
        if url in scan_cache:
            data, timestamp = scan_cache[url]
            if now - timestamp < CACHE_TIME:
                data["success"] = True
                return jsonify(data)

        # 🔥 SAFE URL PARSE
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path

        # ================= SAFE SCANNING =================
        try:
            vulnerabilities = scan_url(url)
        except Exception as e:
            print("VULN ERROR:", e)
            vulnerabilities = []

        try:
            ports = scan_ports(domain)
        except Exception as e:
            print("PORT ERROR:", e)
            ports = []

        try:
            admin_panels = find_admin_panels(url)
        except Exception as e:
            print("ADMIN ERROR:", e)
            admin_panels = []

        # ================= AI =================
        try:
            ai = parallel_ai(vulnerabilities, ports, admin_panels)
        except Exception as e:
            print("AI ERROR:", e)
            ai = {
                "attack_prediction": {},
                "attack_time": {},
                "attack_paths": [],
                "risk_score": 0,
                "risk_level": "LOW",
                "recommendations": ["AI engine failed"]
            }

        result = {
            "success": True,  # 🔥 CRITICAL FIX
            "url": clean_url(url),
            "vulnerabilities": vulnerabilities,
            "ports": ports,
            "admin_panels": admin_panels,
            **ai
        }

        scan_cache[url] = (result, now)

        return jsonify(result)

    except Exception as e:
        print("SCAN ERROR:", e)

        # 🔥 NEVER BREAK FRONTEND
        return jsonify({
            "success": True,
            "url": url,
            "vulnerabilities": ["Scan failed internally"],
            "ports": [],
            "admin_panels": [],
            "attack_prediction": {},
            "attack_time": {},
            "attack_paths": [],
            "risk_score": 0,
            "risk_level": "LOW",
            "recommendations": ["Backend error occurred"]
        })
# ================= REPORT =================
@app.route('/api/download-report', methods=['POST'])
def download_report():

    d = request.json

    # 🔥 Risk class color
    risk_class = {
        "LOW": "#22c55e",
        "MEDIUM": "#eab308",
        "HIGH": "#f97316",
        "CRITICAL": "#ef4444"
    }.get(d["risk_level"], "#22c55e")

    # 🔥 Vulnerability table
    vuln_rows = ""
    for v in d["vulnerabilities"]:
        vuln_rows += f"""
        <tr>
            <td>{v}</td>
            <td style='color:{risk_class}; font-weight:600;'>{d['risk_level']}</td>
        </tr>
        """

    # 🔥 Recommendations
    recommendations_html = "".join(
        f"<li>{r}</li>" for r in d["recommendations"]
    )

    # 🔥 Attack paths
    attack_html = ""
    for i, path in enumerate(d["attack_paths"]):
        attack_html += f"<div class='path'><b>Path {i+1}</b>"
        for step in path:
            attack_html += f"<div class='step'>➤ {step}</div>"
        attack_html += "</div>"

    html = f"""
    <html>
    <head>
        <title>Security Report</title>
        <style>
            body {{
                font-family: Inter;
                background: #0b1220;
                color: #e5e7eb;
                padding: 40px;
            }}

            .container {{
                max-width: 1000px;
                margin: auto;
            }}

            h1 {{
                color: white;
                margin-bottom: 20px;
            }}

            .card {{
                background: #111827;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 20px;
                border: 1px solid #1f2937;
            }}

            .risk {{
                font-size: 28px;
                font-weight: bold;
                color: {risk_class};
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
            }}

            td {{
                padding: 10px;
                border-bottom: 1px solid #1f2937;
            }}

            .path {{
                margin-bottom: 15px;
                padding: 10px;
                background: #0f172a;
                border-radius: 10px;
            }}

            .step {{
                margin: 5px 0;
                padding: 6px;
                background: rgba(255,255,255,0.05);
                border-radius: 6px;
            }}

            ul {{
                padding-left: 20px;
            }}

            .footer {{
                margin-top: 30px;
                text-align: center;
                color: #9ca3af;
                font-size: 12px;
            }}
        </style>
    </head>

    <body>
    <div class="container">

        <h1>🛡 AI Digital Twin Security Report</h1>

        <div class="card">
            <h3>Target</h3>
            <p>{d['url']}</p>
        </div>

        <div class="card">
            <h3>Risk Score</h3>
            <div class="risk">{d['risk_score']}% - {d['risk_level']}</div>
        </div>

        <div class="card">
            <h3>Vulnerability Findings</h3>
            <table>
                {vuln_rows}
            </table>
        </div>

        <div class="card">
            <h3>Attack Paths</h3>
            {attack_html if attack_html else "<p>No attack paths detected</p>"}
        </div>

        <div class="card">
            <h3>Recommendations</h3>
            <ul>
                {recommendations_html}
            </ul>
        </div>

        <div class="footer">
    © {time.strftime('%Y')} AI Digital Twin Hacker | Developed by Manu<br>
    Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}
</div>

    </div>
    </body>
    </html>
    """

    buf = BytesIO()
    buf.write(html.encode())
    buf.seek(0)

    return send_file(buf, as_attachment=True, download_name="security-report.html")

if __name__ == "__main__":
    app.run(debug=True)