import threading
import json
import os
import time

from scanner import Scanner
from scanner import reporting

_jobs = {}
_lock = threading.Lock()

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HISTORY_PATH = os.path.join(BASE, "scan_history.json")
REPORTS_DIR = os.path.join(BASE, "reports")


def _save_history_entry(entry):
    with _lock:
        data = []
        if os.path.exists(HISTORY_PATH):
            try:
                with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []
        # if entry has job_id, replace existing entry with same job_id
        jid = entry.get("job_id")
        if jid is not None:
            replaced = False
            for i, e in enumerate(data):
                if e.get("job_id") == jid:
                    data[i] = entry
                    replaced = True
                    break
            if not replaced:
                data.append(entry)
        else:
            data.append(entry)
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def _run_scan(job_id, target):
    try:
        s = Scanner()
        res = s.scan(target)
        res["job_id"] = job_id
        # write history and export reports
        _save_history_entry(res)
        # create per-job reports (json, csv, html)
        try:
            paths = reporting.write_all_reports(res, REPORTS_DIR, job_id)
            res["reports"] = paths
            # update history entry with report paths
            _save_history_entry(res)
        except Exception:
            pass
        _jobs[job_id] = "completed"
    except Exception:
        _jobs[job_id] = "failed"


def start_scan(target):
    job_id = int(time.time() * 1000)
    _jobs[job_id] = "running"
    t = threading.Thread(target=_run_scan, args=(job_id, target), daemon=True)
    t.start()
    return job_id


def get_history():
    if os.path.exists(HISTORY_PATH):
        try:
            with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def get_result(job_id):
    data = get_history()
    for e in data:
        if e.get("job_id") == job_id:
            return e
    return None


def get_status(job_id):
    return _jobs.get(job_id, "unknown")
