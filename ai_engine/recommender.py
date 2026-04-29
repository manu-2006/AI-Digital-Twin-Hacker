def generate_recommendations(vulnerabilities, ports):
    vulns = [str(v).lower() for v in (vulnerabilities or [])]
    ports = []
    for p in (ports or []):
        try:
            ports.append(int(str(p).split()[0]))
        except:
            continue

    rec = []

    if any("sql" in v for v in vulns):
        rec.append("Use parameterized queries / ORM, enable WAF rules, validate inputs (OWASP A03: Injection).")

    if any("xss" in v for v in vulns):
        rec.append("Sanitize/encode output, implement CSP, use frameworks with auto-escaping (OWASP A03).")

    if any("frame" in v for v in vulns):
        rec.append("Set X-Frame-Options or CSP frame-ancestors to prevent clickjacking.")

    if any("hsts" in v for v in vulns):
        rec.append("Enable HSTS with preload; redirect HTTP→HTTPS.")

    if 22 in ports:
        rec.append("Harden SSH: key-based auth, disable root login, rate-limit, change default port if needed.")

    if 3306 in ports:
        rec.append("Restrict DB access to internal network; enforce auth, TLS, firewall rules.")

    if 23 in ports:
        rec.append("Disable Telnet; replace with SSH.")

    if not rec:
        rec.append("No critical issues detected. Maintain patching, monitoring, and least-privilege access.")

    return rec