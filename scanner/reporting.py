import os
import json
import csv
from html import escape
from datetime import datetime
import zipfile


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def write_json_report(result, out_dir, job_id):
    ensure_dir(out_dir)
    path = os.path.join(out_dir, f"report_{job_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return path


def write_csv_report(result, out_dir, job_id):
    ensure_dir(out_dir)
    path = os.path.join(out_dir, f"report_{job_id}.csv")
    rows = result.get("results", [])
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "url", "severity", "evidence", "payload"])
        for r in rows:
            writer.writerow([r.get("type"), r.get("url"), r.get("severity"), r.get("evidence"), r.get("payload")])
    return path


def write_html_report(result, out_dir, job_id):
    ensure_dir(out_dir)
    path = os.path.join(out_dir, f"report_{job_id}.html")
    rows = result.get("results", [])
    title = f"Scan report {job_id}"

    # summary stats
    counts = {"High": 0, "Medium": 0, "Low": 0}
    by_type = {}
    for r in rows:
        sev = (r.get("severity") or "Low").title()
        counts[sev] = counts.get(sev, 0) + 1
        t = r.get("type") or "Other"
        by_type[t] = by_type.get(t, 0) + 1

    readable_time = ""
    try:
        ts = int(result.get("timestamp") or 0)
        readable_time = datetime.fromtimestamp(ts).isoformat()
    except Exception:
        readable_time = str(result.get("timestamp"))

    json_name = f"report_{job_id}.json"
    csv_name = f"report_{job_id}.csv"
    html_name = f"report_{job_id}.html"

    css = '''
    body{font-family:Segoe UI,Arial,Helvetica,sans-serif;background:#f6f8fa;color:#222}
    .wrap{max-width:1000px;margin:28px auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.08)}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    th,td{padding:10px;border:1px solid #e6e9ef;text-align:left}
    thead th{background:#f0f3f7}
    .severity-High{background:#ffecec;color:#900}
    .severity-Medium{background:#fff4e5;color:#a65a00}
    .severity-Low{background:#eef9ee;color:#1b7a3a}
    .summary{display:flex;gap:12px}
    .summary .card{background:#fbfcfd;padding:10px;border-radius:6px;border:1px solid #eef2f6}
    .links a{margin-right:8px}
    '''

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"<html><head><meta charset=\"utf-8\"><title>{escape(title)}</title>")
        f.write(f"<style>{css}</style></head><body>")
        f.write(f"<div class=\"wrap\">\n<h1>{escape(title)}</h1>\n")
        f.write(f"<p><strong>Start URL:</strong> {escape(result.get('start_url',''))}</p>\n")
        f.write(f"<p><strong>Timestamp:</strong> {escape(readable_time)}</p>\n")
        f.write("<div class=\"summary\">\n")
        f.write(f"<div class=\"card\"><strong>Total findings:</strong> {len(rows)}</div>\n")
        f.write(f"<div class=\"card\"><strong>High:</strong> {counts.get('High',0)}</div>\n")
        f.write(f"<div class=\"card\"><strong>Medium:</strong> {counts.get('Medium',0)}</div>\n")
        f.write(f"<div class=\"card\"><strong>Low:</strong> {counts.get('Low',0)}</div>\n")
        f.write("</div>\n")
        # type breakdown
        if by_type:
            f.write("<h3>By Type</h3><ul>")
            for k,v in by_type.items():
                f.write(f"<li>{escape(str(k))}: {v}</li>")
            f.write("</ul>")

        # links to other report formats
        f.write("<div class=\"links\">\n")
        f.write(f"<a href=\"./{escape(json_name)}\">Download JSON</a>")
        f.write(f"<a href=\"./{escape(csv_name)}\">Download CSV</a>")
        f.write("</div>")

        if not rows:
            f.write("<p>No findings.</p>")
        else:
            f.write("<table><thead><tr><th>Type</th><th>URL</th><th>Severity</th><th>Evidence</th><th>Payload</th></tr></thead><tbody>\n")
            for r in rows:
                sev = (r.get('severity') or 'Low').title()
                cls = f"severity-{escape(sev)}"
                f.write(f"<tr class=\"{cls}\">")
                f.write(f"<td>{escape(str(r.get('type','')))}</td>")
                f.write(f"<td>{escape(str(r.get('url','')))}</td>")
                f.write(f"<td>{escape(sev)}</td>")
                f.write(f"<td>{escape(str(r.get('evidence','')))}</td>")
                f.write(f"<td>{escape(str(r.get('payload','')))}</td>")
                f.write("</tr>\n")
            f.write("</tbody></table>")

        f.write("</div></body></html>")
    return path


def write_all_reports(result, out_dir, job_id):
    ensure_dir(out_dir)
    json_path = write_json_report(result, out_dir, job_id)
    csv_path = write_csv_report(result, out_dir, job_id)
    html_path = write_html_report(result, out_dir, job_id)
    pdf_path = None
    try:
        # optional: pdfkit may not be installed or wkhtmltopdf missing
        import pdfkit
        pdf_path = os.path.join(out_dir, f"report_{job_id}.pdf")
        pdfkit.from_file(html_path, pdf_path)
    except Exception:
        pdf_path = None
    out = {
        "json": json_path,
        "csv": csv_path,
        "html": html_path,
    }
    if pdf_path:
        out["pdf"] = pdf_path
    # create zip of available reports
    try:
        zip_path = os.path.join(out_dir, f"report_{job_id}.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, p in out.items():
                if p and os.path.exists(p):
                    zf.write(p, arcname=os.path.basename(p))
        out["zip"] = zip_path
    except Exception:
        pass
    return out
