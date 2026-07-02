import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class Crawler:
    def __init__(self, session=None):
        self.session = session or requests.Session()

    def fetch(self, url):
        resp = self.session.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text

    def get_links(self, base_url, html):
        soup = BeautifulSoup(html, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if self._same_origin(base_url, href):
                links.add(href.split('#')[0])
        return list(links)

    def get_forms(self, base_url, html):
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            action = urljoin(base_url, action)
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = inp.get("type") or inp.name
                value = inp.get("value") or ""
                inputs.append({"name": name, "type": itype, "value": value})
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def _same_origin(self, a, b):
        pa = urlparse(a)
        pb = urlparse(b)
        return pa.scheme == pb.scheme and pa.netloc == pb.netloc
