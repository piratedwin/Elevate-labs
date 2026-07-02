XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    '" onerror="alert(1)"',
    "<img src=x onerror=alert('xss')>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    '1 OR 1=1',
]

SQL_TESTS = SQLI_PAYLOADS
