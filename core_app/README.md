# Web Application Vulnerability Scanner

Simple Python-based web application vulnerability scanner with a small Flask UI.

Requirements
- Python 3.9+
- Install with: `pip install -r requirements.txt`

Quick start

1. Install dependencies:

```powershell
pip install -r requirements.txt
```

2. Run the web UI:

```powershell
python webapp/app.py
```

3. Open http://127.0.0.1:5000 and enter a target URL (example: http://localhost:8000)

Notes
- This is a simple scanner for demo and learning purposes only. Use it only on systems you own or have explicit permission to test.

Background
----------

This project is a lightweight Web Application Vulnerability Scanner built for learning and authorized testing. Its goal is to demonstrate how basic crawling, form enumeration, injection of test payloads (XSS, SQLi), and simple heuristic detection can be combined with a small web UI to manage scans and generate reports.

Scope and intended use
- Designed for educational purposes and quick security checks against sites you control or have explicit permission to test.
- Not intended to be a replacement for professional scanners or manual penetration testing.

Methodology
- Crawl pages on the same origin and collect links and HTML forms.
- Enumerate form inputs and inject payloads for XSS and SQLi into parameters, then analyze responses for evidence (payload reflection or common SQL error strings).
- Use a simple heuristic to flag potential CSRF risks where POST forms lack token-like fields.
- Record findings with basic severity levels and save results and exportable reports (JSON/CSV/HTML).

Ethics and legal
- Only scan targets you own or have explicit written permission to test.
- Scanning production systems can impact availability; run during maintenance windows where appropriate.

Project layout
- `scanner/`: core scanning, crawling, payloads, detectors, and reporting.
- `webapp/`: Flask UI, background scan manager, templates, and static assets.
- `scan_history.json`: persisted scan history.
- `reports/`: generated per-scan JSON/CSV/HTML reports.

PDF Reports (optional)
- The scanner can optionally generate a PDF version of the HTML report using `pdfkit` and the `wkhtmltopdf` binary.
- To enable PDF export, install the Python package and the `wkhtmltopdf` binary on your system; after installation PDF links will appear in the history UI when available.

Windows installation (recommended):
1. Download the `wkhtmltopdf` Windows installer from https://wkhtmltopdf.org/downloads.html (choose the MSVC build for your Windows version).
2. Run the installer and select the option to add `wkhtmltopdf` to your system `PATH`, or add the installation `bin` folder to `PATH` manually.
3. In your project virtualenv, install the Python wrapper:

```powershell
pip install pdfkit
```

Basic verification:

```powershell
python -c "import pdfkit; print('pdfkit ok')"
where.exe wkhtmltopdf
```

If `where.exe wkhtmltopdf` shows a path and the Python import works, PDF export should succeed when generating reports. If the binary is missing or `pdfkit` is not installed, the scanner will skip PDF generation and still produce JSON/CSV/HTML/ZIP reports.


