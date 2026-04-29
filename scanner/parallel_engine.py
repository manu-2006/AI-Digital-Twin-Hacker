# scanner/parallel_engine.py

from concurrent.futures import ThreadPoolExecutor

def run_parallel_scans(scan_url, scan_ports, find_admin_panels, target):

    results = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_url = executor.submit(scan_url, target)
        future_ports = executor.submit(scan_ports, target)
        future_admin = executor.submit(find_admin_panels, target)

        results["vulns"] = future_url.result()
        results["ports"] = future_ports.result()
        results["admin"] = future_admin.result()

    return results