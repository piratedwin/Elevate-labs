from flask import Flask, render_template, request, redirect, url_for, send_file, abort, jsonify
import shutil
from scanner import Scanner
from . import scan_manager

app = Flask(__name__)


@app.route("/", methods=["GET"]) 
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"]) 
def scan():
    target = request.form.get("target")
    if not target:
        return redirect(url_for("index"))
    job_id = scan_manager.start_scan(target)
    return redirect(url_for("history"))


@app.route("/history", methods=["GET"])
def history():
    entries = scan_manager.get_history()
    return render_template("history.html", entries=entries)


@app.route("/result/<int:job_id>", methods=["GET"])
def view_result(job_id):
    res = scan_manager.get_result(job_id)
    if not res:
        return ("Result not found", 404)
    return render_template("results.html", result=res)


@app.route("/download/<int:job_id>/<fmt>", methods=["GET"])
def download_report(job_id, fmt):
    res = scan_manager.get_result(job_id)
    if not res:
        return ("Result not found", 404)
    reports = res.get("reports") or {}
    path = reports.get(fmt)
    if not path or not os.path.exists(path):
        return ("Report not available", 404)
    try:
        return send_file(path, as_attachment=True)
    except Exception:
        return abort(500)


if __name__ == "__main__":
    app.run(debug=True)


@app.route('/status', methods=['GET'])
def status():
    """Return JSON showing whether PDF generation is available."""
    pdfkit_ok = False
    wk_path = None
    try:
        import pdfkit  # noqa: F401
        pdfkit_ok = True
    except Exception:
        pdfkit_ok = False
    try:
        wk_path = shutil.which('wkhtmltopdf')
    except Exception:
        wk_path = None
    return jsonify({
        'pdfkit_installed': pdfkit_ok,
        'wkhtmltopdf_path': wk_path,
        'pdf_generation_available': pdfkit_ok and bool(wk_path)
    })
