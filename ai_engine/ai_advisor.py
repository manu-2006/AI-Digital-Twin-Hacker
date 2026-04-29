def generate_ai_advice(vulnerabilities):

    advice = set()  # use set to avoid duplicates

    # Normalize
    vulnerabilities = [v.lower() for v in vulnerabilities]

    # ===== XSS =====
    if any("xss" in v or "content security policy" in v for v in vulnerabilities):
        advice.add("Sanitize all user inputs and enable Content Security Policy (CSP)")
        advice.add("Disable inline scripts and use secure headers to prevent XSS")

    # ===== Clickjacking =====
    if any("frame" in v for v in vulnerabilities):
        advice.add("Add X-Frame-Options header (DENY or SAMEORIGIN)")
        advice.add("Use Content Security Policy frame-ancestors directive")

    # ===== SSL / HSTS =====
    if any("hsts" in v for v in vulnerabilities):
        advice.add("Enable HTTP Strict Transport Security (HSTS)")
        advice.add("Redirect all HTTP traffic to HTTPS")

    # ===== Admin Panels =====
    advice.add("Restrict admin panel access using IP filtering or authentication")
    advice.add("Use strong passwords and enable multi-factor authentication (MFA)")

    # ===== Ports =====
    advice.add("Close unnecessary open ports to reduce attack surface")
    advice.add("Use firewall rules to restrict unauthorized access")

    # ===== DEFAULT =====
    if not advice:
        advice.add("System appears secure. Continue regular monitoring and updates")

    return list(advice)