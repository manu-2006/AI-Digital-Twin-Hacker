import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def find_admin_panels(url):

    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # ✅ Fixed list (comma added)
        paths = [
            "admin",
            "administrator",
            "admin/login",
            "dashboard",
            "login",
            "adminpanel",
            "wp-admin",
            "phpmyadmin",
            "cpanel",
            "user",
            "backend",
            "panel",
            "admin/dashboard"
        ]

        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        found = set()

        # 🔥 Single request checker
        def check_path(path):
            try:
                test_url = f"{base_url}/{path}"

                r = requests.get(
                    test_url,
                    headers=headers,
                    timeout=2,           # ⚡ faster
                    allow_redirects=True
                )

                if r.status_code in [200, 301, 302, 401, 403]:
                    return r.url.rstrip("/")

            except requests.exceptions.RequestException:
                return None

        # ⚡ PARALLEL EXECUTION
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_path, p) for p in paths]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)

        return sorted(list(found))

    except Exception as e:
        print("Admin Finder Error:", e)
        return []