# ai_engine/realtime_recommender.py
import time

def stream_recommendations(vulnerabilities):
    for vuln in vulnerabilities:
        name = vuln.get("name", "")

        if "sql" in name.lower():
            yield f"[AI] SQL Injection detected → Use parameterized queries immediately"

        elif "admin" in name.lower():
            yield f"[AI] Admin panel exposed → Enforce authentication & IP restriction"

        elif "xss" in name.lower():
            yield f"[AI] XSS risk → Implement input sanitization"

        else:
            yield f"[AI] General vulnerability → Apply patching and monitoring"

        time.sleep(1)  # simulate real-time thinking