import os
import json
import socket
import textwrap
import requests
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from PIL import Image, ImageDraw, ImageFont
from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

# ==============================================================================
# 1. YOUR API KEYS (Configured from your credentials)
# ==============================================================================
API_KEYS = {
    "VIRUSTOTAL": "ecee9a89784ca26c8baeb0fe116c6274a8b04d20e5663d53517edc94a4bff15e",
    "CENSYS_PAT": "censys_A2Bwp49G_Jb6STb63QuP2TmR48QcFFzkm",
    "SHODAN": "wI9z8sX7jW3RdSco7ZOGKc3BZRqJc19y",
    "ABUSEIPDB": "087a19960beec8074cccf60111458dbb3423d88ec18a03ee243850e7d654f4ece46cf96331387a53",
    "CRIMINALIP": "IpO9V9o7yFVIR4ADhrKDR6yg1V9xhrw2SwnIrJ4lk8eyvEIS1OAoIBLknqhp",
    "BUILTWITH": "dfae5779-585a-48ea-a03a-8812aaada49a",
    "IPINFO": "ad5e24719e8884",
    # Optional 8th API key (if left blank, script uses crt.sh Lab-1 SSL OSINT)
    "SECURITYTRAILS": ""
}

# ==============================================================================
# 2. TARGET NORMALIZER & DNS RESOLVER
# ==============================================================================
def normalize_target(target: str) -> tuple[str, str]:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    domain = urlparse(target).netloc.split(":")[0].lower()
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        ip_address = "Unresolved"
    return domain, ip_address

# ==============================================================================
# 3. AUTOMATIC SCREENSHOT GENERATOR WITH TIMESTAMP OVERLAY
# ==============================================================================
def save_timestamped_screenshot(folder: str, step_num: str, tool_name: str, target: str, ip: str, summary: dict, raw_data: dict):
    """Generates a clean terminal-style PNG evidence screenshot with exact timestamp."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    file_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tool = tool_name.replace(" ", "_").replace(".", "")
    img_path = os.path.join(folder, f"{step_num}_{safe_tool}_{file_ts}.png")

    # Format text lines
    raw_pretty = json.dumps(raw_data, indent=2, default=str)
    wrapped_lines = []
    for line in raw_pretty.splitlines()[:32]:  # Cap at 32 lines for crisp readability
        wrapped_lines.extend(textwrap.wrap(line, width=95) or [""])

    header_lines = [
        f"===============================================================================================",
        f"  OSINT LAB EVIDENCE CAPTURE  |  TOOL #{step_num}: {tool_name.upper()}",
        f"  TARGET DOMAIN: {target}   |   RESOLVED IP: {ip}",
        f"  EXECUTION TIMESTAMP: {now_str}",
        f"===============================================================================================",
        f"  STATUS         : {summary.get('Status')}",
        f"  RISK / VERDICT : {summary.get('Risk / Verdict')}",
        f"  KEY FINDINGS   : {summary.get('Key Findings')}",
        f"-----------------------------------------------------------------------------------------------",
        f"  RAW API RESPONSE PREVIEW:",
        f"-----------------------------------------------------------------------------------------------",
    ]

    all_lines = header_lines + wrapped_lines
    line_height = 20
    width = 980
    height = max(420, (len(all_lines) + 3) * line_height)

    img = Image.new("RGB", (width, height), color=(18, 22, 28))
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("consola.ttf", 14)
        bold_font = ImageFont.truetype("consolab.ttf", 15)
    except IOError:
        try:
            font = ImageFont.truetype("DejaVuSansMono.ttf", 14)
            bold_font = ImageFont.truetype("DejaVuSansMono-Bold.ttf", 15)
        except IOError:
            font = ImageFont.load_default()
            bold_font = font

    # Top accent banner
    draw.rectangle([(0, 0), (width, 8)], fill=(0, 180, 216))

    y = 20
    for idx, line in enumerate(all_lines):
        if idx in (1, 2, 3):
            draw.text((20, y), line, fill=(0, 230, 180), font=bold_font)
        elif idx in (5, 6, 7):
            draw.text((20, y), line, fill=(255, 215, 100), font=font)
        elif idx in (0, 4, 8, 10):
            draw.text((20, y), line, fill=(90, 110, 130), font=font)
        else:
            draw.text((20, y), line, fill=(220, 228, 235), font=font)
        y += line_height

    # Bottom timestamp watermark bar
    draw.rectangle([(0, height - 30), (width, height)], fill=(28, 35, 45))
    draw.text((20, height - 23), f"Verified OSINT Automated Capture | Timestamp: {now_str} | File: {os.path.basename(img_path)}", fill=(140, 200, 255), font=font)

    img.save(img_path)
    return img_path

# ==============================================================================
# 4. EIGHT OSINT TOOL FUNCTIONS (FROM LECTURE 01 LAB)
# ==============================================================================

def query_virustotal(domain: str):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": API_KEYS["VIRUSTOTAL"]}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        data = r.json()
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": str(data)[:110], "Risk / Verdict": "API Error"}, data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        registrar = attrs.get("registrar", "N/A")
        rep = attrs.get("reputation", 0)
        verdict = "Malicious" if mal > 0 else ("Suspicious" if susp > 0 else "Clean")
        summary = {
            "Status": "Success",
            "Key Findings": f"Detections: {mal}/{total} | Reputation: {rep} | Registrar: {registrar}",
            "Risk / Verdict": verdict
        }
        return summary, {"registrar": registrar, "reputation": rep, "last_analysis_stats": stats}
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

def query_censys(ip: str):
    if ip == "Unresolved":
        return {"Status": "Skipped", "Key Findings": "Unresolved IP", "Risk / Verdict": "N/A"}, {}
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    headers = {
        "Authorization": f"Bearer {API_KEYS['CENSYS_PAT']}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json"
    }
    try:
        r = requests.get(url, headers=headers, timeout=15)
        # Fallback to v2 endpoint if PAT is scoped to Legacy Search API
        if r.status_code in (401, 403, 404):
            url_v2 = f"https://search.censys.io/api/v2/hosts/{ip}"
            r = requests.get(url_v2, headers={"Authorization": f"Bearer {API_KEYS['CENSYS_PAT']}"}, timeout=15)
        data = r.json()
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": str(data)[:110], "Risk / Verdict": "Check Token Scope"}, data
        res = data.get("result", data)
        services = res.get("services", [])
        ports = [f"{s.get('port')}/{s.get('service_name', s.get('protocol', ''))}" for s in services]
        asn = res.get("autonomous_system", {}).get("name", "N/A")
        loc = res.get("location", {}).get("country", "N/A")
        summary = {
            "Status": "Success",
            "Key Findings": f"Exposed Services: {', '.join(ports[:6]) or 'None'} | ASN: {asn} | Country: {loc}",
            "Risk / Verdict": f"{len(ports)} Open Services"
        }
        return summary, {"ip": ip, "asn": asn, "country": loc, "services": ports[:10]}
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

def query_shodan(ip: str):
    if ip == "Unresolved":
        return {"Status": "Skipped", "Key Findings": "Unresolved IP", "Risk / Verdict": "N/A"}, {}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={API_KEYS['SHODAN']}"
    try:
        r = requests.get(url, timeout=15)
        data = r.json()
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": str(data)[:110], "Risk / Verdict": "API Error"}, data
        ports = data.get("ports", [])
        org = data.get("org", "N/A")
        isp = data.get("isp", "N/A")
        vulns = data.get("vulns", [])
        summary = {
            "Status": "Success",
            "Key Findings": f"Open Ports: {ports} | Org: {org} | ISP: {isp}",
            "Risk / Verdict": f"{len(vulns)} CVEs Found" if vulns else "No Known CVEs"
        }
        return summary, {"ip": ip, "org": org, "isp": isp, "ports": ports, "vulns": vulns[:10]}
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

def query_abuseipdb(ip: str):
    if ip == "Unresolved":
        return {"Status": "Skipped", "Key Findings": "Unresolved IP", "Risk / Verdict": "N/A"}, {}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEYS["ABUSEIPDB"], "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
        data = r.json()
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": str(data)[:110], "Risk / Verdict": "API Error"}, data
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        reports = d.get("totalReports", 0)
        usage = d.get("usageType", "N/A")
        isp = d.get("isp", "N/A")
        verdict = "High Risk" if score >= 50 else ("Suspicious" if score > 0 else "Clean (0% Abuse)")
        summary = {
            "Status": "Success",
            "Key Findings": f"Abuse Score: {score}% | Reports: {reports} | Usage: {usage} | ISP: {isp}",
            "Risk / Verdict": verdict
        }
        return summary, d
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

def query_criminalip(ip: str):
    if ip == "Unresolved":
        return {"Status": "Skipped", "Key Findings": "Unresolved IP", "Risk / Verdict": "N/A"}, {}
    url = f"https://api.criminalip.io/v1/asset/ip/report/summary?ip={ip}"
    headers = {"x-api-key": API_KEYS["CRIMINALIP"]}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        data = r.json()
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": str(data)[:110], "Risk / Verdict": "API Error"}, data
        score = data.get("score", {})
        inbound = score.get("inbound", "N/A")
        outbound = score.get("outbound", "N/A")
        isp = data.get("isp", "N/A")
        country = data.get("country", "N/A")
        summary = {
            "Status": "Success",
            "Key Findings": f"Inbound Risk: {inbound} | Outbound Risk: {outbound} | ISP: {isp} ({country})",
            "Risk / Verdict": f"Inbound: {inbound}"
        }
        return summary, data
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

def query_builtwith(domain: str):
    url = f"https://api.builtwith.com/free1/api.json?KEY={API_KEYS['BUILTWITH']}&LOOKUP={domain}"
    try:
        r = requests.get(url, timeout=15)
        data = r.json()
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": str(data)[:110], "Risk / Verdict": "API Error"}, data
        groups = data.get("groups", [])
        tech_list = [f"{g.get('name')} ({g.get('live', 0)} live)" for g in groups[:6]]
        summary = {
            "Status": "Success",
            "Key Findings": f"Tech Stack: {', '.join(tech_list) if tech_list else 'No public stack groups'}",
            "Risk / Verdict": f"{len(groups)} Tech Categories"
        }
        return summary, {"domain": domain, "groups": groups[:8]}
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

def query_ipinfo(ip: str):
    if ip == "Unresolved":
        return {"Status": "Skipped", "Key Findings": "Unresolved IP", "Risk / Verdict": "N/A"}, {}
    url = f"https://ipinfo.io/{ip}/json?token={API_KEYS['IPINFO']}"
    try:
        r = requests.get(url, timeout=15)
        data = r.json()
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": str(data)[:110], "Risk / Verdict": "API Error"}, data
        city = data.get("city", "N/A")
        region = data.get("region", "N/A")
        country = data.get("country", "N/A")
        org = data.get("org", "N/A")
        summary = {
            "Status": "Success",
            "Key Findings": f"Location: {city}, {region}, {country} | ASN/Org: {org}",
            "Risk / Verdict": "Informational (Geo/ASN)"
        }
        return summary, data
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

def query_crtsh_or_securitytrails(domain: str):
    """8th Lab-1 Tool: SecurityTrails (if key provided) or crt.sh Certificate Transparency API"""
    if API_KEYS.get("SECURITYTRAILS"):
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers = {"APIKEY": API_KEYS["SECURITYTRAILS"], "Accept": "application/json"}
        try:
            r = requests.get(url, headers=headers, timeout=15)
            data = r.json()
            sub_count = data.get("subdomain_count", 0)
            return {
                "Status": "Success",
                "Key Findings": f"Subdomains Found: {sub_count}",
                "Risk / Verdict": "DNS/Subdomain Profiled"
            }, data
        except Exception as e:
            return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

    # crt.sh JSON API (Mentioned in Lecture 01 Lab Section 1.3.2 & 1.3.5)
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return {"Status": f"HTTP {r.status_code}", "Key Findings": "crt.sh busy/rate-limited", "Risk / Verdict": "Retry"}, {}
        certs = r.json()
        unique_names = set()
        issuers = set()
        for c in certs:
            for name in str(c.get("name_value", "")).splitlines():
                unique_names.add(name.strip())
            issuers.add(str(c.get("issuer_name", "")).split("O=")[-1].split(",")[0])
        sample_subs = sorted(list(unique_names))[:5]
        summary = {
            "Status": "Success",
            "Key Findings": f"SSL Certs: {len(certs)} | Unique Subdomains: {len(unique_names)} | Sample: {', '.join(sample_subs)}",
            "Risk / Verdict": "SSL/Subdomains Mapped"
        }
        return summary, {"total_certs": len(certs), "unique_subdomains_count": len(unique_names), "sample_subdomains": sample_subs, "issuers": list(issuers)[:4]}
    except Exception as e:
        return {"Status": "Error", "Key Findings": str(e), "Risk / Verdict": "Error"}, {"error": str(e)}

# ==============================================================================
# 5. PROFESSIONAL EXCEL (.XLSX) REPORT GENERATOR
# ==============================================================================
def export_to_excel(df_summary: pd.DataFrame, df_raw: pd.DataFrame, domain: str, ip: str, run_ts: str) -> str:
    file_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"OSINT_Comparison_{domain.replace('.', '_')}_{file_ts}.xlsx"

    with pd.ExcelWriter(filename, engine="openpyxl") as writer:
        df_summary.to_excel(writer, sheet_name="Comparison Table", index=False, startrow=3)
        df_raw.to_excel(writer, sheet_name="Raw API Evidence", index=False, startrow=3)

    wb = load_workbook(filename)

    # Style Sheet 1: Comparison Table
    ws1 = wb["Comparison Table"]
    ws1["A1"] = f"OSINT Website Investigation & Multi-Tool Comparison Report — {domain}"
    ws1["A1"].font = Font(size=14, bold=True, color="1F4E78")
    ws1["A2"] = f"Target Website: {domain}   |   Resolved IPv4: {ip}   |   Execution Timestamp: {run_ts}"
    ws1["A2"].font = Font(size=10, italic=True, color="404040")

    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=11)
    zebra_fill = PatternFill(start_color="F2F6FA", end_color="F2F6FA", fill_type="solid")
    thin_border = Border(
        left=Side(style="thin", color="D0D7DE"),
        right=Side(style="thin", color="D0D7DE"),
        top=Side(style="thin", color="D0D7DE"),
        bottom=Side(style="thin", color="D0D7DE"),
    )

    for cell in ws1[4]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = thin_border

    for row_idx in range(5, ws1.max_row + 1):
        ws1.row_dimensions[row_idx].height = 36
        for col_idx in range(1, ws1.max_column + 1):
            cell = ws1.cell(row=row_idx, column=col_idx)
            cell.border = thin_border
            cell.alignment = Alignment(vertical="center", wrap_text=True, horizontal="center" if col_idx in (1, 4, 6) else "left")
            if row_idx % 2 == 1:
                cell.fill = zebra_fill

    widths_s1 = {"A": 6, "B": 18, "C": 26, "D": 14, "E": 56, "F": 22, "G": 34}
    for col, w in widths_s1.items():
        ws1.column_dimensions[col].width = w

    # Style Sheet 2: Raw API Evidence
    ws2 = wb["Raw API Evidence"]
    ws2["A1"] = f"Raw JSON API Outputs & Timestamps — {domain}"
    ws2["A1"].font = Font(size=13, bold=True, color="1F4E78")
    ws2["A2"] = f"Target: {domain} ({ip}) | Timestamp: {run_ts}"
    ws2["A2"].font = Font(size=10, italic=True, color="404040")

    for cell in ws2[4]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = thin_border

    for row_idx in range(5, ws2.max_row + 1):
        ws2.row_dimensions[row_idx].height = 95
        for col_idx in range(1, ws2.max_column + 1):
            cell = ws2.cell(row=row_idx, column=col_idx)
            cell.border = thin_border
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    ws2.column_dimensions["A"].width = 18
    ws2.column_dimensions["B"].width = 24
    ws2.column_dimensions["C"].width = 95

    wb.save(filename)
    return filename

# ==============================================================================
# 6. MAIN EXECUTION
# ==============================================================================
def main():
    print("=" * 75)
    print("  OSINT TASK 1: MULTI-TOOL WEBSITE ANALYZER + EXCEL & SCREENSHOT GENERATOR")
    print("=" * 75)
    raw_target = input("Enter target website (e.g., tesla.com or upes.ac.in): ").strip()
    domain, ip = normalize_target(raw_target)
    run_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    folder_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    screenshot_dir = f"OSINT_Screenshots_{domain.replace('.', '_')}_{folder_ts}"
    os.makedirs(screenshot_dir, exist_ok=True)

    print(f"\n[*] Target Domain : {domain}")
    print(f"[*] Resolved IPv4 : {ip}")
    print(f"[*] Start Time    : {run_timestamp}")
    print(f"[*] Screenshots   : ./{screenshot_dir}/\n")

    eighth_tool_name = "SecurityTrails" if API_KEYS.get("SECURITYTRAILS") else "crt.sh (SSL CT)"

    pipeline = [
        ("01", "VirusTotal", "Malware & Vendor Reputation", lambda: query_virustotal(domain)),
        ("02", "Censys", "Attack Surface & Exposed Ports", lambda: query_censys(ip)),
        ("03", "Shodan", "Open Ports, Org & Banner Info", lambda: query_shodan(ip)),
        ("04", "AbuseIPDB", "IP Abuse & Blacklist Confidence", lambda: query_abuseipdb(ip)),
        ("05", "CriminalIP", "Inbound/Outbound Threat Risk", lambda: query_criminalip(ip)),
        ("06", "BuiltWith", "Web Technology Stack Profiler", lambda: query_builtwith(domain)),
        ("07", "IPinfo", "IP Geolocation & ASN Details", lambda: query_ipinfo(ip)),
        ("08", eighth_tool_name, "SSL Certificates & Subdomains", lambda: query_crtsh_or_securitytrails(domain)),
    ]

    summary_rows = []
    raw_rows = []

    for step, name, category, func in pipeline:
        tool_exec_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{tool_exec_time}] Running Tool {step}: {name}...")
        summary, raw_json = func()

        img_path = save_timestamped_screenshot(
            folder=screenshot_dir,
            step_num=step,
            tool_name=name,
            target=domain,
            ip=ip,
            summary=summary,
            raw_data=raw_json
        )
        print(f"    └── Screenshot saved: {img_path}")

        summary_rows.append({
            "#": step,
            "OSINT Tool": name,
            "Category": category,
            "API Status": summary["Status"],
            "Key Findings": summary["Key Findings"],
            "Risk / Verdict": summary["Risk / Verdict"],
            "Screenshot File": os.path.basename(img_path)
        })

        raw_rows.append({
            "OSINT Tool": name,
            "Timestamp": tool_exec_time,
            "Raw JSON Output": json.dumps(raw_json, indent=2, default=str)[:3000]
        })

    df_summary = pd.DataFrame(summary_rows)
    df_raw = pd.DataFrame(raw_rows)

    print("\n" + "=" * 100)
    print(f"FINAL COMPARISON TABLE: {domain} ({ip}) | {run_timestamp}")
    print("=" * 100)
    print(df_summary.drop(columns=["Screenshot File"]).to_markdown(index=False))

    excel_filename = export_to_excel(df_summary, df_raw, domain, ip, run_timestamp)
    print(f"\n[✓] Excel Report Saved : {excel_filename}")
    print(f"[✓] All 8 Timestamped Screenshots Saved in Folder : {screenshot_dir}/")

if __name__ == "__main__":
    main()