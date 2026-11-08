import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from scanner.config import TARGET, START_PATH, MAX_PAGES, SKIP_WORDS
from scanner.checks.headers import check_headers, check_redirects


# ---------- Helpers ----------
def normalize(url):
    parsed = urlparse(url.split("#")[0])
    if parsed.path == "":
        parsed = parsed._replace(path="/")
    return parsed.geturl()


def should_skip(url):
    return any(word in url.lower() for word in SKIP_WORDS)


def extract_forms(url, soup):
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


# ---------- The crawl ----------
def crawl(session):
    """Crawl the target. Returns (visited, findings, forms)."""
    start_url = normalize(TARGET + START_PATH)
    base_domain = urlparse(start_url).netloc

    visited = set()
    to_visit = [start_url]
    all_findings = []
    all_forms = []

    while to_visit and len(visited) < MAX_PAGES:
        url = to_visit.pop(0)

        if url in visited or should_skip(url):
            continue

        print("Visiting:", url)
        response = session.get(url)
        visited.add(url)

        all_findings.extend(check_headers(url, response))
        all_findings.extend(check_redirects(url, response))

        if "text/html" not in response.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        all_forms.extend(extract_forms(url, soup))

        for link in soup.find_all("a"):
            href = link.get("href")
            if not href:
                continue
            full_url = normalize(urljoin(url, href))

            if urlparse(full_url).netloc == base_domain and full_url not in visited:
                to_visit.append(full_url)

        time.sleep(0.3)

    return visited, all_findings, all_forms


# ---------- Report (moves to report.py in Step 5) ----------
def print_report(visited, all_findings, all_forms):
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


# ---------- Runs only when you do: python crawler.py ----------
if __name__ == "__main__":
    session = make_session()
    print("Session ready.\n")
    visited, all_findings, all_forms = crawl(session)
    print_report(visited, all_findings, all_forms)