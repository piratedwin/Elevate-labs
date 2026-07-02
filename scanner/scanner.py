import json
import time
from urllib.parse import urlparse, parse_qs, urlencode
import requests

from .crawler import Crawler
from .payloads import XSS_PAYLOADS, SQL_TESTS
from .detectors import detect_xss, detect_sqli, detect_csrf


class Scanner:
    def __init__(self, session=None, logger_path="scan_results.json"):
        self.session = session or requests.Session()
        self.crawler = Crawler(self.session)
        self.logger_path = logger_path

    def scan(self, start_url, max_pages=20):
        results = []
        visited = set()
        to_visit = [start_url]
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                html = self.crawler.fetch(url)
            except Exception as e:
                continue

            links = self.crawler.get_links(url, html)
            for l in links:
                if l not in visited:
                    to_visit.append(l)

            forms = self.crawler.get_forms(url, html)

            # CSRF checks
            for form in forms:
                if detect_csrf(form):
                    results.append({
                        "type": "CSRF",
                        "url": form.get("action"),
                        "evidence": "Form missing token-like hidden input",
                        "severity": "Medium",
                        "owasp": detect_csrf.__module__ and __import__('scanner.detectors').detectors.owasp_for('CSRF') if False else __import__('scanner.detectors').detectors.owasp_for('CSRF')
                    })

            # Test forms for XSS/SQLi
            for form in forms:
                action = form.get("action")
                method = form.get("method", "get").lower()
                data = {inp["name"]: inp.get("value", "test") for inp in form.get("inputs", [])}
                for payload in XSS_PAYLOADS:
                    test_data = data.copy()
                    # inject into first param
                    if test_data:
                        first = next(iter(test_data))
                        test_data[first] = payload
                    try:
                        if method == "post":
                            resp = self.session.post(action, data=test_data, timeout=10)
                        else:
                            resp = self.session.get(action, params=test_data, timeout=10)
                    except Exception:
                        continue
                    if detect_xss(resp.text, payload):
                        results.append({
                            "type": "XSS",
                            "url": action,
                            "payload": payload,
                            "evidence": payload,
                            "severity": "High",
                            "owasp": __import__('scanner.detectors').detectors.owasp_for('XSS'),
                        })

                for sqli in SQL_TESTS:
                    test_data = data.copy()
                    if test_data:
                        first = next(iter(test_data))
                        test_data[first] = sqli
                    try:
                        if method == "post":
                            resp = self.session.post(action, data=test_data, timeout=10)
                        else:
                            resp = self.session.get(action, params=test_data, timeout=10)
                    except Exception:
                        continue
                    if detect_sqli(resp.text):
                        results.append({
                            "type": "SQLi",
                            "url": action,
                            "payload": sqli,
                            "evidence": "Database error string in response",
                            "severity": "High",
                            "owasp": __import__('scanner.detectors').detectors.owasp_for('SQLi'),
                        })

            # Test GET query params for XSS/SQLi
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            if qs:
                for payload in XSS_PAYLOADS:
                    params = {k: payload for k in qs.keys()}
                    try:
                        resp = self.session.get(parsed._replace(query="").geturl(), params=params, timeout=10)
                    except Exception:
                        continue
                    if detect_xss(resp.text, payload):
                        results.append({
                            "type": "XSS",
                            "url": url,
                            "payload": payload,
                            "evidence": payload,
                            "severity": "High",
                            "owasp": __import__('scanner.detectors').detectors.owasp_for('XSS'),
                        })
                for sqli in SQL_TESTS:
                    params = {k: sqli for k in qs.keys()}
                    try:
                        resp = self.session.get(parsed._replace(query="").geturl(), params=params, timeout=10)
                    except Exception:
                        continue
                    if detect_sqli(resp.text):
                        results.append({
                            "type": "SQLi",
                            "url": url,
                            "payload": sqli,
                            "evidence": "Database error string in response",
                            "severity": "High",
                            "owasp": __import__('scanner.detectors').detectors.owasp_for('SQLi'),
                        })

        # write results
        timestamp = int(time.time())
        out = {"start_url": start_url, "timestamp": timestamp, "results": results}
        try:
            with open(self.logger_path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
        except Exception:
            pass
        return out


def quick_scan(url):
    s = Scanner()
    return s.scan(url)
