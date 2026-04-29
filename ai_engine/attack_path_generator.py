def generate_attack_paths(vulnerabilities, open_ports, admin_panels):

    try:
        # ✅ Safe defaults
        vulnerabilities = vulnerabilities or []
        open_ports = open_ports or []
        admin_panels = admin_panels or []

        paths = []

        # =============================
        # 🔐 Normalize inputs
        # =============================
        vuln_list = []
        for v in vulnerabilities:
            try:
                vuln_list.append(str(v).lower())
            except:
                continue

        port_list = []
        for p in open_ports:
            try:
                port_list.append(int(p))
            except:
                continue

        # =============================
        # 🧠 Attack path logic
        # =============================

        # XSS
        if any("xss" in v for v in vuln_list):
            paths.append([
                "Inject malicious script",
                "Steal session cookies",
                "Hijack user session"
            ])

        # Clickjacking
        if any("frame" in v for v in vuln_list):
            paths.append([
                "Embed iframe",
                "Perform clickjacking",
                "Trigger unauthorized actions"
            ])

        # SQL Injection
        if any("sql" in v for v in vuln_list):
            paths.append([
                "Inject SQL payload",
                "Bypass authentication",
                "Extract database data"
            ])

        # Admin panels
        if admin_panels:
            paths.append([
                "Discover admin panel",
                "Attempt credential brute force",
                "Gain administrative access"
            ])

        # MySQL
        if 3306 in port_list:
            paths.append([
                "Detect MySQL service",
                "Attempt remote connection",
                "Extract sensitive data"
            ])

        # SSH
        if 22 in port_list:
            paths.append([
                "Identify SSH service",
                "Attempt brute force login",
                "Gain server shell access"
            ])

        # HTTP (basic attack surface)
        if 80 in port_list:
            paths.append([
                "Scan web server",
                "Identify vulnerabilities",
                "Exploit exposed endpoints"
            ])

        return paths

    except Exception as e:
        print("Attack Path Error:", e)
        return []