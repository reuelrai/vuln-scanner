import requests
from bs4 import BeautifulSoup

TARGET = "http://localhost:8080"
MARKER = 'zq7431<b>"\''


def make_session(level):
    """Return a logged-in DVWA session at the given security level."""
    session = requests.Session()
    page = session.get(TARGET + "/login.php")
    soup = BeautifulSoup(page.text, "html.parser")
    token = soup.find("input", {"name": "user_token"})["value"]
    session.post(TARGET + "/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token,
    })

    for cookie in session.cookies:
        if cookie.name == "security":
            cookie.value = level

    home = session.get(TARGET + "/index.php")
    if f"<em>Security Level:</em> {level}" not in home.text:
        raise SystemExit(f"Could not set security level to {level}")

    return session


def get_hidden_values(session, page_url):
    """Load a page and return its hidden form fields (like user_token)."""
    page = session.get(page_url)
    soup = BeautifulSoup(page.text, "html.parser")
    values = {}
    for field in soup.find_all("input", {"type": "hidden"}):
        name = field.get("name")
        if name:
            values[name] = field.get("value", "")
    return values


def probe_field(session, form, field_name):
    """Send the marker through one field. Returns: raw / escaped / blocked / not reflected."""
    params = get_hidden_values(session, form["page"])     # fresh token every time

    for field in form["inputs"]:
        params.setdefault(field["name"], "test")          # fill the other fields
    params[field_name] = MARKER                           # marker goes in this one

    text = session.get(form["action"], params=params).text

    if "csrf token is incorrect" in text.lower():
        return "blocked"
    if MARKER in text:
        return "raw"
    if "zq7431" in text:
        return "escaped"
    return "not reflected"


def check_reflected_xss(session, form):
    """Returns (findings, outcomes) for a GET form."""
    findings = []
    outcomes = {}

    if form["method"] != "get":
        return findings, outcomes                         # POST forms come later

    for field in form["inputs"]:
        if field["type"] == "hidden":
            continue                                      # don't attack token fields

        outcome = probe_field(session, form, field["name"])
        outcomes[field["name"]] = outcome

        if outcome == "raw":
            findings.append({
                "url": form["action"],
                "issue": f"Potential reflected XSS in field '{field['name']}'",
                "severity": "High",
            })
    return findings, outcomes


xss_form = {
    "page": TARGET + "/vulnerabilities/xss_r/",
    "action": TARGET + "/vulnerabilities/xss_r/",
    "method": "get",
    "inputs": [{"name": "name", "type": "text"}],
}

for level in ["low", "medium", "high", "impossible"]:
    session = make_session(level)
    findings, outcomes = check_reflected_xss(session, xss_form)
    print(f"{level:11} | outcomes: {outcomes} | findings: {len(findings)}")