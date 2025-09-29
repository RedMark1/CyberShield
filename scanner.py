
import requests
import socket
import ssl
import datetime
from urllib.parse import urlparse

# ----- Config -----
TIMEOUT = 8
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]
COMMON_ENDPOINTS = [
    "/", "/robots.txt", "/sitemap.xml", "/admin/", "/login", "/.git/", "/backup/", "/env", "/wp-admin/"
]
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ----- Helper functions -----
def normalize_url(user_input: str) -> str:
    if not user_input.startswith(("http://", "https://")):
        user_input = "https://" + user_input
    return user_input.rstrip("/")

def fetch_headers(url: str):
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"SafeSiteScanner/1.0"})
        return {"status_code": r.status_code, "final_url": r.url, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

def check_security_headers(headers: dict):
    missing = []
    present = {}
    for h in SECURITY_HEADERS:
        if h in headers:
            present[h] = headers[h]
        else:
            missing.append(h)
    return {"present": present, "missing": missing}

def fetch_robots_sitemap(base_url):
    results = {}
    for p in ["/robots.txt", "/sitemap.xml"]:
        try:
            url = base_url.rstrip("/") + p
            r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent":"SafeSiteScanner/1.0"})
            results[p] = {"status_code": r.status_code, "length": len(r.text)}
        except Exception as e:
            results[p] = {"error": str(e)}
    return results

def get_tls_certificate(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer")
                }
    except Exception as e:
        return {"error": str(e)}

def check_common_endpoints(base_url):
    results = {}
    for p in COMMON_ENDPOINTS:
        try:
            url = base_url.rstrip("/") + p
            r = requests.head(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"SafeSiteScanner/1.0"})
            if r.status_code == 405: # Method Not Allowed, try GET
                r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"SafeSiteScanner/1.0"})
            results[p] = {"status_code": r.status_code, "final_url": r.url}
        except Exception as e:
            results[p] = {"error": str(e)}
    return results

def fetch_cve_info(keyword):
    """Fetch CVE info from NVD for a given keyword."""
    if not keyword: return []
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        r = requests.get(NVD_API_URL, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            items = []
            for cve in data.get("vulnerabilities", []):
                cve_id = cve["cve"]["id"]
                desc = cve["cve"]["descriptions"][0]["value"]
                cvss = cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                items.append({
                    "CVE ID": cve_id,
                    "CVSS": cvss,
                    "Description": desc,
                    "Component": keyword
                })
            return items
        return []
    except Exception:
        return []

def run_full_scan(target_url: str, include_endpoints: bool):
    """
    Runs all scanning steps and returns a comprehensive report dictionary.
    This function will be called by our Flask backend.
    """
    base = normalize_url(target_url)
    parsed = urlparse(base)
    hostname = parsed.hostname or ""

    scan_report = {
        "target": base,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "results": {}
    }

    # Step 1: HTTP fetch
    http_info = fetch_headers(base)
    scan_report["results"]["http_fetch"] = http_info

    # Step 2: Security headers
    server_banner = None
    if isinstance(http_info, dict) and "headers" in http_info:
        headers = http_info["headers"]
        scan_report["results"]["security_headers"] = check_security_headers(headers)
        server_banner = headers.get("Server") or headers.get("X-Powered-By")
    else:
        scan_report["results"]["security_headers"] = {"error": "Failed to fetch headers"}

    # Step 3: TLS Certificate
    if hostname:
        scan_report["results"]["tls_certificate"] = get_tls_certificate(hostname)
    else:
        scan_report["results"]["tls_certificate"] = {"error": "Invalid hostname"}

    # Step 4: Robots.txt & Sitemap.xml
    scan_report["results"]["robots_sitemap"] = fetch_robots_sitemap(base)

    # Step 5: Common endpoints (if enabled)
    if include_endpoints:
        scan_report["results"]["common_endpoints"] = check_common_endpoints(base)
    else:
        scan_report["results"]["common_endpoints"] = {"skipped": "Endpoints check disabled"}

    # Step 6: CVE Info
    cve_results = []
    if server_banner:
        cve_results.extend(fetch_cve_info(server_banner))
    scan_report["results"]["cve_info"] = cve_results

    return scan_report
