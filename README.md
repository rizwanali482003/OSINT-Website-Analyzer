# OSINT-Website-Analyzer
Automated Python OSINT reconnaissance tool integrating 8 threat intelligence &amp; infrastructure APIs (VirusTotal, Censys, Shodan, AbuseIPDB, CriminalIP, BuiltWith, IPinfo, crt.sh) with formatted Excel comparison reports and timestamped PNG evidence capture.
# Automated Multi-Tool OSINT Website & IP Intelligence Analyzer

An automated Python reconnaissance and threat intelligence script built for **OSINT Lab Task 1 (Domain URL & IP Address Intelligence)**. The tool queries **8 OSINT platforms**, compiles a side-by-side comparison report in **Excel (`.xlsx`)**, and automatically captures **timestamped PNG screenshots** of each tool's execution output.

## Tools Integrated
1. **VirusTotal** – Domain reputation, registrar details, and security vendor malware detections.
2. **Censys** – Internet-facing host scan, exposed ports/services, and ASN intelligence.
3. **Shodan** – Open ports, service banners, ISP/organization metadata, and CVE exposure.
4. **AbuseIPDB** – IP abuse confidence score, historical threat reports, and usage classification.
5. **CriminalIP** – Inbound/outbound threat risk scoring and asset exposure summary.
6. **BuiltWith** – Web technology stack profiling (CMS, frameworks, analytics, and hosting).
7. **IPinfo** – Geolocation, ASN, and network ownership metadata.
8. **crt.sh (Certificate Transparency)** – SSL/TLS certificate logs and passive subdomain enumeration.

## Key Features
* **Automated Multi-API Pipeline:** Resolves target domains to IPv4 and queries all 8 intelligence sources sequentially.
* **Formatted Excel Report (`.xlsx`):** Generates a two-sheet workbook containing a structured **Comparison Table** and **Raw API Evidence**.
* **Timestamped Evidence Screenshots (`.png`):** Renders terminal-style visual captures stamped with exact execution date, time, target domain, and IP address.

## Setup & Usage
1. Install dependencies:
   ```bash
   python -m pip install requests pandas openpyxl pillow tabulate
