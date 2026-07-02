from scanner.detectors import detect_xss, detect_sqli, detect_csrf, owasp_for


def test_detect_xss_reflection():
    payload = "<script>alert('xss')</script>"
    # reflected escaped
    resp = "Some text &lt;script&gt;alert('xss')&lt;/script&gt; other"
    assert detect_xss(resp, payload)


def test_detect_sqli_error():
    resp = "Fatal error: You have an error in your SQL syntax near 'FROM'"
    assert detect_sqli(resp)


def test_detect_csrf():
    form_with_token = {"method": "post", "inputs": [{"name": "csrf_token", "type": "hidden"}]}
    assert detect_csrf(form_with_token) is False
    form_without = {"method": "post", "inputs": [{"name": "search", "type": "text"}]}
    assert detect_csrf(form_without) is True


def test_owasp_mapping():
    assert 'Cross-Site Scripting' in owasp_for('XSS')
    assert 'Injection' in owasp_for('SQLi')
    assert 'Cross-Site Request Forgery' in owasp_for('CSRF')
