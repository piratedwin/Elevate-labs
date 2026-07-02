from scanner.crawler import Crawler


def test_get_links_and_forms():
    with open('tests/fixtures/sample.html', 'r', encoding='utf-8') as f:
        html = f.read()

    base = 'http://example.local/'
    c = Crawler()
    links = c.get_links(base, html)
    assert 'http://example.local/page1' in links
    assert 'http://example.local/page2' in links

    forms = c.get_forms(base, html)
    # two forms
    assert len(forms) == 2
    f0 = forms[0]
    assert f0['action'].endswith('/submit1')
    assert any(inp['name'] == 'q' for inp in f0['inputs'])
