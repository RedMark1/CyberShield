
"""
app.py
SafeSiteScanner (improved UI + progress)

- Presents results in an easy-to-read structure (summary cards, tables, expanders)
- Shows progress bar, step-by-step status messages, spinner, and elapsed time
- Still non-intrusive: headers, TLS certificate metadata, robots/sitemap, HEAD checks for common endpoints
- Only scan sites you own or have explicit permission to test.
"""

import streamlit as st
import requests
import socket
import ssl
import json
import datetime
import time
import os
from urllib.parse import urlparse
import pandas as pd
import matplotlib.pyplot as plt
import base64
import networkx as nx
import google.generativeai as genai

GOOGLE_API_KEY = "AIzaSyDZc824cmYrzTYjgvk2jGvqI61Lsfuv_Cw"  # <-- Your Gemini API key

try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

st.set_page_config(page_title="SafeSiteScanner (Improved)", layout="wide")

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
HISTORY_FILE = "scan_history.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ----- Helper functions -----
def normalize_url(user_input: str) -> str:
    if not user_input.startswith(("http://", "https://")):
        user_input = "https://" + user_input  # prefer HTTPS by default
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
                notAfter = cert.get("notAfter")
                notBefore = cert.get("notBefore")
                subject = cert.get("subject")
                issuer = cert.get("issuer")
                return {"notBefore": notBefore, "notAfter": notAfter, "subject": subject, "issuer": issuer}
    except Exception as e:
        return {"error": str(e)}

def check_common_endpoints(base_url):
    results = {}
    for p in COMMON_ENDPOINTS:
        try:
            url = base_url.rstrip("/") + p
            r = requests.head(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"SafeSiteScanner/1.0"})
            if r.status_code == 405:
                r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"SafeSiteScanner/1.0"})
            results[p] = {"status_code": r.status_code, "final_url": r.url}
        except Exception as e:
            results[p] = {"error": str(e)}
    return results

def parse_cert_expiry(notAfter: str):
    if not notAfter:
        return None
    # Example format: 'Jul  6 12:00:00 2025 GMT'
    try:
        dt = datetime.datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
        return dt
    except Exception:
        try:
            # fallback: attempt without timezone
            dt = datetime.datetime.strptime(notAfter, "%b %d %H:%M:%S %Y")
            return dt
        except Exception:
            return None

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []

def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def fetch_cve_info(keyword):
    """Fetch CVE info from NVD for a given keyword (e.g., server banner, component)."""
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": 3}
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
        else:
            return []
    except Exception as e:
        return []

def highlight_attack_paths(vulns):
    """Highlight high-risk vulnerabilities (CVSS >= 7)."""
    high_risk = [v for v in vulns if v.get("CVSS") != "N/A" and float(v["CVSS"]) >= 7]
    return high_risk

def gemini_explain_vulnerability(vuln):
    if not GOOGLE_API_KEY:
        return "Google Gemini API key not set."
    prompt = (
        f"Explain this web vulnerability and suggest remediation steps:\n\n"
        f"{vuln['Description']}\n\nComponent: {vuln['Component']}\nCVSS: {vuln['CVSS']}\n"
    )
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Gemini AI assistant error: {e}"

def generate_scan_report_html(report):
    """Converts the scan report dictionary to a styled HTML string."""
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: sans-serif; margin: 2em; }}
            h1, h2, h3 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; word-break: break-word; }}
            th {{ background-color: #f2f2f2; }}
            .code {{ background-color: #eee; padding: 5px; font-family: monospace; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>SafeSiteScanner Report</h1>
        <p><strong>Target:</strong> {report.get('target')}</p>
        <p><strong>Scanned At:</strong> {report.get('scanned_at')}</p>
        <p><strong>Elapsed Time:</strong> {report.get('elapsed_seconds', 'N/A')}s</p>
    """

    # HTTP Fetch
    html += "<h2>HTTP Fetch Results</h2>"
    http_fetch = report.get('results', {}).get('http_fetch', {})
    if isinstance(http_fetch, dict):
        html += "<table>"
        for key, value in http_fetch.items():
            if key == 'headers':
                headers_str = "<br>".join([f"{k}: {v}" for k, v in value.items()])
                html += f"<tr><th>{key}</th><td>{headers_str}</td></tr>"
            else:
                html += f"<tr><th>{key}</th><td>{value}</td></tr>"
        html += "</table>"
    else:
        html += f"<p>{http_fetch}</p>"

    # Security Headers
    html += "<h2>Security Headers</h2>"
    sec_headers = report.get('results', {}).get('security_headers', {})
    if isinstance(sec_headers, dict):
        html += "<table>"
        for key, value in sec_headers.items():
            # Pretty print lists or dicts
            if isinstance(value, (list, dict)):
                val_str = json.dumps(value, indent=2)
                html += f"<tr><th>{key}</th><td><pre>{val_str}</pre></td></tr>"
            else:
                html += f"<tr><th>{key}</th><td>{value}</td></tr>"
        html += "</table>"
    else:
        html += f"<p>{sec_headers}</p>"

    # TLS Info
    html += "<h2>TLS Certificate</h2>"
    tls = report.get('results', {}).get('tls', {})
    if isinstance(tls, dict):
        if tls.get("skipped"):
            html += "<p>Skipped (target is not HTTPS).</p>"
        else:
            html += "<table>"
            for key, value in tls.items():
                val_str = json.dumps(value, indent=2) if isinstance(value, (dict, list)) else value
                html += f"<tr><th>{key}</th><td><pre>{val_str}</pre></td></tr>"
            html += "</table>"
    else:
        html += f"<p>{tls}</p>"

    # Robots & Sitemap
    html += "<h2>Robots.txt & Sitemap</h2>"
    robots = report.get('results', {}).get('robots_sitemap', {})
    if isinstance(robots, dict) and robots:
        html += "<table>"
        for key, value in robots.items():
            val_str = json.dumps(value, indent=2) if isinstance(value, dict) else value
            html += f"<tr><th>{key}</th><td><pre>{val_str}</pre></td></tr>"
        html += "</table>"
    else:
        html += "<p>No data found.</p>"

    # Common Endpoints
    html += "<h2>Common Endpoints</h2>"
    endpoints = report.get('results', {}).get('common_endpoints', {})
    if isinstance(endpoints, dict) and endpoints:
        html += "<table><tr><th>Path</th><th>Details</th></tr>"
        for key, value in endpoints.items():
            val_str = json.dumps(value, indent=2) if isinstance(value, dict) else value
            html += f"<tr><td>{key}</td><td><pre>{val_str}</pre></td></tr>"
        html += "</table>"
    else:
        html += "<p>No endpoints checked or found.</p>"

    html += "</body></html>"
    return html

# ----- Caching -----
@st.cache_data(ttl=3600)  # Cache for 1 hour
def fetch_headers(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"SafeSiteScanner/1.0"})
        return {"status_code": r.status_code, "final_url": r.url, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

# ----- UI -----
st.title("SafeSiteScanner — improved UI & progress")
st.markdown("**Legal & ethical reminder:** Only scan sites you own or are explicitly authorized to test. This tool performs passive checks only.")

# Initialize vuln_report here so it exists on first run
vuln_report = []

with st.form("scan_form"):
    target = st.text_input("Target URL or domain (e.g. example.com or https://example.com)", value="")
    include_endpoints = st.checkbox("Include common endpoint checks (HEAD requests)", value=True)
    submit = st.form_submit_button("Start scan")

# Sidebar: Scan history
st.sidebar.header("Scan History")
history = load_history()
if history:
    selected = st.sidebar.selectbox(
        "View previous scan results",
        options=[f"{h.get('target', 'Unknown')} ({h.get('scanned_at', 'N/A')})" for h in history],
        index=0
    )
    # Use .get() for safe access to avoid KeyError if a history item is malformed
    idx = [f"{h.get('target', 'Unknown')} ({h.get('scanned_at', 'N/A')})" for h in history].index(selected)
    if st.sidebar.button("Show selected scan"):
        st.session_state['show_history'] = idx

if st.sidebar.button("Start new scan"):
    st.session_state['show_history'] = None

# Show previous scan result if selected
if st.session_state.get('show_history') is not None:
    prev = history[st.session_state['show_history']]
    st.header(f"Previous Scan: {prev['target']}")
    st.write(f"Scanned at: {prev['scanned_at']}")
    st.json(prev)
    st.stop()

if submit:
    if not target:
        st.error("Please provide a target domain or URL.")
    else:
        base = normalize_url(target)
        parsed = urlparse(base)
        hostname = parsed.hostname or ""
        st.info(f"Starting non-intrusive scan of: **{base}**")

        # Prepare UI placeholders
        progress = st.progress(0.0)
        status_placeholder = st.empty()
        timer_placeholder = st.empty()

        steps = [
            ("Resolving & basic HTTP fetch", "http"),
            ("Checking security headers", "sec_headers"),
            ("TLS certificate check", "tls"),
            ("Fetching robots.txt & sitemap.xml", "robots"),
            ("Common endpoints (HEAD)", "endpoints") if include_endpoints else None,
            ("Summarize & produce report", "summary")
        ]
        steps = [s for s in steps if s is not None]
        total_steps = len(steps)
        step_idx = [0]  # <-- change to a list
        start_time = time.perf_counter()

        scan_report = {
            "target": base,
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "results": {}
        }

        def advance(step_name):
            step_idx[0] += 1  # <-- update the list value
            fraction = step_idx[0] / total_steps
            progress.progress(fraction)
            status_placeholder.info(f"Step {step_idx[0]}/{total_steps}: {step_name}")
            elapsed = time.perf_counter() - start_time
            timer_placeholder.markdown(f"**Elapsed:** {elapsed:.1f}s")

        # Step 1: HTTP fetch
        with st.spinner("Fetching target (HTTP GET)..."):
            advance("Resolving & basic HTTP fetch")
            http_info = fetch_headers(base)
            scan_report["results"]["http_fetch"] = http_info
            # Quick summary card area
            col1, col2, col3, col4 = st.columns(4)
            # Status code
            code = http_info.get("status_code") if isinstance(http_info, dict) else None
            col1.metric("Status code", code if code is not None else "Error")
            # Final URL
            col2.metric("Final URL", http_info.get("final_url") if isinstance(http_info, dict) else "—")
            # Server banner if present
            server_banner = None
            if isinstance(http_info, dict) and "headers" in http_info:
                server_banner = http_info["headers"].get("Server") or http_info["headers"].get("X-Powered-By")
            col3.metric("Server banner", server_banner if server_banner else "Not exposed")
            # Security headers present count (temp)
            pres_cnt = 0
            if isinstance(http_info, dict) and "headers" in http_info:
                pres_cnt = sum([1 for h in SECURITY_HEADERS if h in http_info["headers"]])
            col4.metric("Security headers present", f"{pres_cnt}/{len(SECURITY_HEADERS)}")

        # Step 2: Security headers
        with st.spinner("Analyzing security headers..."):
            advance("Checking security headers")
            sec = {}
            if isinstance(http_info, dict) and "headers" in http_info:
                sec = check_security_headers(http_info["headers"])
            else:
                sec = {"error": "No headers to analyze"}
            scan_report["results"]["security_headers"] = sec

            with st.expander("Security headers summary"):
                if "error" in sec:
                    st.error(sec["error"])
                else:
                    if sec["missing"]:
                        st.warning(f"Missing: {', '.join(sec['missing'])}")
                    else:
                        st.success("All common security headers present.")
                    st.write("Present headers:")
                    st.json(sec.get("present", {}))

        # Step 3: TLS certificate
        tls_info = {}
        with st.spinner("Checking TLS certificate (if HTTPS)..."):
            advance("TLS certificate check")
            if parsed.scheme == "https" and hostname:
                tls_info = get_tls_certificate(hostname)
                scan_report["results"]["tls"] = tls_info
                if "error" in tls_info:
                    st.error(f"TLS check error: {tls_info['error']}")
                else:
                    notAfter = tls_info.get("notAfter")
                    expire_dt = parse_cert_expiry(notAfter)
                    days_left = None
                    if expire_dt:
                        days_left = (expire_dt - datetime.datetime.utcnow()).days
                    col1, col2 = st.columns(2)
                    col1.subheader("Certificate expiry")
                    col1.write(f"Not after: {notAfter or 'Unknown'}")
                    if days_left is not None:
                        if days_left < 0:
                            col1.error(f"Expired {abs(days_left)} day(s) ago")
                        elif days_left < 30:
                            col1.warning(f"Expires in {days_left} day(s)")
                        else:
                            col1.success(f"Expires in {days_left} day(s)")
                    col2.subheader("Certificate issuer / subject")
                    col2.write(tls_info.get("issuer"))
                    col2.write(tls_info.get("subject"))
            else:
                st.info("Target is not HTTPS or hostname not parsed; skipping TLS check.")
                scan_report["results"]["tls"] = {"skipped": True}

        # Step 4: robots & sitemap
        with st.spinner("Fetching robots.txt and sitemap.xml..."):
            advance("Fetching robots.txt & sitemap.xml")
            robots = fetch_robots_sitemap(base)
            scan_report["results"]["robots_sitemap"] = robots
            with st.expander("robots.txt & sitemap.xml details"):
                st.json(robots)

        # Step 5: common endpoints (optional)
        endpoints_res = {}
        if include_endpoints:
            with st.spinner("Checking common endpoints (HEAD requests)..."):
                advance("Common endpoints (HEAD)")
                endpoints_res = check_common_endpoints(base)
                scan_report["results"]["common_endpoints"] = endpoints_res
                # present a small table summarizing endpoints with 2xx
                success_endpoints = []
                for p, v in endpoints_res.items():
                    code = v.get("status_code") if isinstance(v, dict) else None
                    if isinstance(code, int) and 200 <= code < 300:
                        success_endpoints.append((p, code, v.get("final_url", "")))
                if success_endpoints:
                    st.success(f"Accessible endpoints: {', '.join([p for p,_,_ in success_endpoints])}")
                    st.table([{"path": p, "status": c, "resolved_url": u} for p,c,u in success_endpoints])
                else:
                    st.info("No common endpoints returned 2xx (or none accessible).")

        # Final step: summary and report
        advance("Summarize & produce report")
        elapsed_total = time.perf_counter() - start_time
        progress.progress(1.0)
        status_placeholder.success("Scan completed.")
        timer_placeholder.markdown(f"**Total elapsed:** {elapsed_total:.1f}s")

        # Build human-friendly summary panel
        st.header("Summary")
        summary_cols = st.columns(4)
        # overall reachability
        http_status = http_info.get("status_code") if isinstance(http_info, dict) else None
        summary_cols[0].metric("Reachable", "Yes" if isinstance(http_info, dict) and "headers" in http_info else "No")
        summary_cols[1].metric("HTTP status", http_status if http_status else "—")
        # TLS status
        tls_status = "Skipped"
        if scan_report["results"].get("tls"):
            if scan_report["results"]["tls"].get("error"):
                tls_status = "Error"
            elif scan_report["results"]["tls"].get("skipped"):
                tls_status = "Skipped"
            else:
                na = scan_report["results"]["tls"].get("notAfter")
                exp_dt = parse_cert_expiry(na)
                if exp_dt:
                    days = (exp_dt - datetime.datetime.utcnow()).days
                    tls_status = f"{days} days left" if days is not None else "Valid"
                else:
                    tls_status = "Valid (unknown expiry format)"
        summary_cols[2].metric("TLS", tls_status)
        # Security headers missing count
        missing = scan_report["results"].get("security_headers", {}).get("missing", [])
        summary_cols[3].metric("Missing security headers", len(missing))

        # Recommendations (simple, defensive)
        st.header("Quick recommendations")
        recs = []
        if missing:
            recs.append("Add missing security headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy).")
        if scan_report["results"].get("tls", {}).get("error"):
            recs.append("Investigate TLS / certificate issues reported.")
        if server_banner:
            recs.append("Consider hiding or limiting server banners (Server / X-Powered-By) to reduce fingerprinting.")
        robot_data = scan_report["results"].get("robots_sitemap", {}).get("/robots.txt", {})
        if robot_data.get("status_code") == 200:
            recs.append("Review robots.txt — it is public and may expose paths you don't want indexed.")
        if include_endpoints and scan_report["results"].get("common_endpoints"):
            found = [p for p,v in scan_report["results"]["common_endpoints"].items() if isinstance(v, dict) and 200 <= v.get("status_code",0) < 300 and p != "/"]
            if found:
                recs.append(f"Accessible endpoints discovered: {', '.join(found)} — review access controls and remove sensitive content from public paths.")
        if not recs:
            recs.append("No quick findings. For a deeper audit, perform an authorized, full security assessment (passive + active testing by professionals).")
        for r in recs:
            st.markdown("- " + r)

        # Raw JSON report and download
        st.header("Downloadable report & raw output")
        scan_report["elapsed_seconds"] = round(elapsed_total, 2)
        report_json = json.dumps(scan_report, indent=2, default=str)
        st.download_button("Download JSON report", data=report_json, file_name="safesitescanner_report.json", mime="application/json")
        with st.expander("Raw JSON report"):
            st.code(report_json, language="json")

        # Generate and download PDF report
        if PDFKIT_AVAILABLE:
            try:
                html_content = generate_scan_report_html(scan_report)
                pdf_bytes = pdfkit.from_string(html_content, False)
                st.download_button(
                    "Download PDF report",
                    data=pdf_bytes,
                    file_name="safesitescanner_report.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.error(f"Could not generate PDF: {e}")
        else:
            st.info("PDF export requires pdfkit and wkhtmltopdf installed.")

        # After scan completes, save to history
        if submit and 'results' in scan_report:
            history.insert(0, scan_report)
            save_history(history)

        # --- Vulnerability Report Section ---
        st.header("Structured Vulnerability Report")
        vuln_report = []

        # Example: Use server banner as a component to search for CVEs
        if server_banner:
            st.subheader(f"Threat Intelligence for: {server_banner}")
            cve_data = fetch_cve_info(server_banner)
            if cve_data:
                st.table(cve_data)
                vuln_report.extend(cve_data)
            else:
                st.info("No CVEs found for this component.")

        # Example: Missing security headers as vulnerabilities
        for missing_header in missing:
            vuln_report.append({
                "CVE ID": "N/A",
                "CVSS": "N/A",
                "Description": f"Missing security header: {missing_header}",
                "Component": "Web Server"
            })

        # Highlight attack paths (high-risk vulns)
        high_risk = highlight_attack_paths(vuln_report)
        if high_risk:
            st.warning("High-risk vulnerabilities detected (CVSS >= 7):")
            st.table(high_risk)
        else:
            st.success("No high-risk vulnerabilities detected based on available data.")

        # Downloadable vulnerability report
        st.download_button(
            "Download Vulnerability Report (JSON)",
            data=json.dumps(vuln_report, indent=2),
            file_name="vulnerability_report.json",
            mime="application/json"
        )

        # --- Structured Reporting Section ---
        st.header("Structured Vulnerability Report")

        # Convert vuln_report to DataFrame for charts/tables
        df_vuln = pd.DataFrame(vuln_report)
        if not df_vuln.empty:
            st.subheader("Vulnerability Table")
            st.dataframe(df_vuln)

            # Chart: Vulnerabilities by Component
            st.subheader("Vulnerabilities by Component")
            comp_counts = df_vuln['Component'].value_counts()
            fig1, ax1 = plt.subplots()
            comp_counts.plot(kind='bar', ax=ax1)
            ax1.set_ylabel("Count")
            ax1.set_xlabel("Component")
            st.pyplot(fig1)

            # Chart: High vs Low Risk (CVSS)
            st.subheader("Risk Level Distribution")
            def risk_level(cvss):
                try:
                    score = float(cvss)
                    if score >= 7:
                        return "High"
                    elif score >= 4:
                        return "Medium"
                    else:
                        return "Low"
                except:
                    return "Unknown"
            df_vuln['Risk'] = df_vuln['CVSS'].apply(risk_level)
            risk_counts = df_vuln['Risk'].value_counts()
            fig2, ax2 = plt.subplots()
            risk_counts.plot(kind='pie', autopct='%1.0f%%', ax=ax2)
            ax2.set_ylabel("")
            st.pyplot(fig2)

            # Summary report
            st.subheader("Summary Report")
            st.markdown(f"- **Total vulnerabilities:** {len(df_vuln)}")
            st.markdown(f"- **High risk:** {sum(df_vuln['Risk']=='High')}")
            st.markdown(f"- **Medium risk:** {sum(df_vuln['Risk']=='Medium')}")
            st.markdown(f"- **Low risk:** {sum(df_vuln['Risk']=='Low')}")
            st.markdown(f"- **Unknown risk:** {sum(df_vuln['Risk']=='Unknown')}")

            # Optional: PDF export
            if PDFKIT_AVAILABLE:
                st.subheader("Export Vulnerability Report as PDF")
                html = df_vuln.to_html(index=False)
                pdf_bytes = pdfkit.from_string(html, False)
                b64 = base64.b64encode(pdf_bytes).decode()
                href = f'<a href="data:application/pdf;base64,{b64}" download="vulnerability_report.pdf">Download PDF report</a>'
                st.markdown(href, unsafe_allow_html=True)
            else:
                st.info("PDF export requires pdfkit and wkhtmltopdf installed.")

        else:
            st.info("No vulnerabilities found to report.")

# --- Upload and combine external reports ---
st.sidebar.header("Combine External Reports")
uploaded_files = st.sidebar.file_uploader(
    "Upload JSON reports from other tools (Nmap, Nessus, etc.)",
    type=["json"], accept_multiple_files=True
)
external_vulns = []
for uploaded_file in uploaded_files:
    try:
        data = json.load(uploaded_file)
        # Assume a list of vulnerabilities or a dict with 'vulnerabilities' key
        if isinstance(data, list):
            external_vulns.extend(data)
        elif isinstance(data, dict) and 'vulnerabilities' in data:
            external_vulns.extend(data['vulnerabilities'])
    except Exception as e:
        st.sidebar.error(f"Failed to load {uploaded_file.name}: {e}")

# Merge with current vuln_report after scan
if submit:
    # ...existing scan code...
    # After vuln_report is built:
    if external_vulns:
        st.info(f"Merging {len(external_vulns)} vulnerabilities from external reports.")
        vuln_report.extend(external_vulns)

    # --- Attack Path Visualization ---
    st.header("Attack Path Visualization")
    if vuln_report:
        # Build a simple graph: Component → Vulnerability → Risk
        G = nx.DiGraph()
        for v in vuln_report:
            comp = v.get("Component", "Unknown")
            desc = v.get("Description", "Vulnerability")
            risk = v.get("CVSS", "N/A")
            node_vuln = f"{desc[:30]}..." if len(desc) > 30 else desc
            node_risk = f"Risk: {risk}"
            G.add_node(comp, color='lightblue')
            G.add_node(node_vuln, color='orange')
            G.add_node(node_risk, color='red' if risk != "N/A" and float(risk) >= 7 else 'yellow')
            G.add_edge(comp, node_vuln)
            G.add_edge(node_vuln, node_risk)

        pos = nx.spring_layout(G, k=0.5)
        node_colors = [G.nodes[n].get('color', 'gray') for n in G.nodes()]
        fig, ax = plt.subplots(figsize=(8, 5))
        nx.draw(G, pos, with_labels=True, node_color=node_colors, ax=ax, font_size=8, arrows=True)
        st.pyplot(fig)
        st.markdown("**Attack path graph:** Components → Vulnerabilities → Risk levels")
    else:
        st.info("No vulnerabilities to visualize attack paths.")

# --- AI Assistant Section ---
st.header("AI Assistant: Vulnerability Explanations & Remediation (Gemini)")
if vuln_report:
    for vuln in vuln_report[:3]:  # Limit to first 3 for demo
        st.subheader(f"{vuln.get('Description', 'Vulnerability')}")
        explanation = gemini_explain_vulnerability(vuln)
        st.markdown(explanation)
else:
    st.info("No vulnerabilities found for AI assistant to explain.")
