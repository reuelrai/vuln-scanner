import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# ---------- Settings ----------
TARGET = "http://127.0.0.1:5500/index.html"
START_PATH = "/index.php"
MAX_PAGES = 40
SKIP_WORDS = ["logout", "setup"]      # never visit URLs containing these
IMPORTANT_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]


# ---------- Helpers ----------
def normalize(url):
    parsed = urlparse(url.split("#")[0])
    if parsed.path == "":
        parsed = parsed._replace(path="/")
    return parsed.geturl()


def should_skip(url):
    return any(word in url.lower() for word in SKIP_WORDS)


def login_dvwa(session):
    """Log in to DVWA and set difficulty to Low. Returns True on success."""
    page = session.get(TARGET + "/login.php")
    soup = BeautifulSoup(page.text, "html.parser")
    token = soup.find("input", {"name": "user_token"})["value"]

    data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token,
    }
    result = session.post(TARGET + "/login.php", data=data)
    session.cookies.set("security", "low")
    return "Logout" in result.text


# ---------- Checks ----------
def check_headers(url, response):
    findings = []
    for header in IMPORTANT_HEADERS:
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
    findings = []
    if url.startswith("https://") and response.url.startswith("http://"):
        findings.append({
            "url": url,
            "issue": "HTTPS request redirected to insecure HTTP",
            "severity": "Medium",
        })
    return findings


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


# ---------- Main crawl ----------
session = requests.Session()

if not login_dvwa(session):
    print("Login failed. Is DVWA running and the database created?")
    raise SystemExit(1)
print("Logged in!\n")

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

# ---------- Report ----------
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