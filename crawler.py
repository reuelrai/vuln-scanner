import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def normalize(url):
    parsed = urlparse(url.split("#")[0])   # drop #fragments, then split the URL into parts
    if parsed.path == "":                  # "https://site.com" -> "https://site.com/"
        parsed = parsed._replace(path="/")
    return parsed.geturl()


start_url = normalize("https://quotes.toscrape.com")
base_domain = urlparse(start_url).netloc
max_pages = 10

important_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]


def check_headers(url, response):
    """Return a list of findings for missing security headers."""
    findings = []
    
    for header in important_headers:
        if header == "Strict-Transport-Security" and response.url.startswith("http://"):
            continue
        if header not in response.headers:
            findings.append({
                "url": url,
                "issue": "Missing header: " + header,
                "severity": "Low",
            })
    return findings


def check_redirects(url, response):
    """Flag pages where an HTTPS request ended up on plain HTTP."""
    findings = []
    if url.startswith("https://") and response.url.startswith("http://"):
        findings.append({
            "url": url,
            "issue": "HTTPS request redirected to insecure HTTP",
            "severity": "Medium",
        })
    return findings


def extract_forms(url, soup):
    """Return a list of forms found on a page."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = form.get("method", "get").lower()

        inputs = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if name:
                inputs.append({"name": name, "type": field.get("type", "text")})

        forms.append({
            "page": url,
            "action": urljoin(url, action),
            "method": method,
            "inputs": inputs,
        })
    return forms


visited = set()
to_visit = [start_url]
all_findings = []
all_forms = []

while to_visit and len(visited) < max_pages:
    url = to_visit.pop(0)

    if url in visited:
        continue

    print("Visiting:", url)
    response = requests.get(url)
    visited.add(url)

    all_findings.extend(check_headers(url, response))
    all_findings.extend(check_redirects(url, response))

    soup = BeautifulSoup(response.text, "html.parser")
    all_forms.extend(extract_forms(url, soup))

    for link in soup.find_all("a"):
        href = link.get("href")
        full_url = normalize(urljoin(url, href))

        if urlparse(full_url).netloc == base_domain and full_url not in visited:
            to_visit.append(full_url)

    time.sleep(1)

print("\n--- SCAN REPORT ---")
print("Pages scanned:", len(visited))

grouped = {}
for finding in all_findings:
    key = (finding["severity"], finding["issue"])
    grouped.setdefault(key, []).append(finding["url"])

for (severity, issue), urls in grouped.items():
    print(f"[{severity}] {issue}  (on {len(urls)} pages)")

print("\nForms found:", len(all_forms))
for f in all_forms:
    names = [i["name"] for i in f["inputs"]]
    print(f"  {f['method'].upper()} {f['action']}  inputs: {names}")