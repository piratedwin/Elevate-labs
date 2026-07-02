import re
import html


SQL_ERROR_RE = re.compile(
    r"you have an error in your sql syntax|mysql_fetch|supplied argument is not a valid|unclosed quotation mark|syntax error at or near|ORA-|PG::SyntaxError|SQL syntax|Warning: pg_|SQLite\.Exception|Unknown column|ODBC|SQLSTATE",
    re.I,
)


XSS_REFLECTION_RE = re.compile(r"<[^>]*>.*</|script|onerror|onload", re.I)


def detect_xss(response_text, payload):
    if not response_text:
        return False
    # direct reflection
    if payload in response_text:
        return True
    # check unescaped response for reflected payload
    try:
        if payload in html.unescape(response_text):
            return True
    except Exception:
        pass
    # escaped reflection
    esc = html.escape(payload)
    if esc in response_text:
        return True
    # heuristic: look for suspicious script-like fragments
    if XSS_REFLECTION_RE.search(response_text) and any(tag in response_text.lower() for tag in ["<script", "onerror=", "onload="]):
        return True
    return False


def detect_sqli(response_text):
    if not response_text:
        return False
    if SQL_ERROR_RE.search(response_text):
        return True
    return False


def detect_csrf(form):
    # heuristic: look for hidden inputs with token-like names; if present, not vulnerable
    for inp in form.get("inputs", []):
        name = inp.get("name", "").lower()
        itype = inp.get("type", "").lower()
        if itype == "hidden" and ("csrf" in name or "token" in name or "auth" in name):
            return False
    # if it's a POST form and no token-like hidden inputs, flag as potential CSRF
    return form.get("method", "get").lower() == "post"


def owasp_for(vuln_type):
    t = (vuln_type or "").lower()
    if "xss" in t or "cross-site" in t:
        return "Cross-Site Scripting (OWASP Top 10)"
    if "sqli" in t or "sql" in t or "injection" in t:
        return "Injection (OWASP Top 10)"
    if "csrf" in t:
        return "Cross-Site Request Forgery (OWASP Top 10)"
    return "Other (OWASP Top 10)"
