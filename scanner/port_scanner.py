import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_ports(domain):

    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL"
    }

    open_ports = []

    # 🔥 Single port scanner
    def check_port(port, service):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # ⚡ faster timeout
            result = s.connect_ex((domain, port))
            s.close()

            if result == 0:
                return f"{port} ({service})"
        except:
            return None

    # ⚡ Parallel execution
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(check_port, port, service)
            for port, service in common_ports.items()
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return open_ports