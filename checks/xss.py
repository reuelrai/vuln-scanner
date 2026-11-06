from bs4 import BeautifulSoup
from config import SKIP_FIELD_TYPES

MARKER = 'zq7431<b>"\''


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
    """Test a GET form. Returns a list of findings, like every other check."""
    findings = []

    if form["method"] != "get":
        return findings                                   # POST forms come later

    for field in form["inputs"]:
        if field["type"] in SKIP_FIELD_TYPES:
            continue

        outcome = probe_field(session, form, field["name"])

        if outcome == "raw":
            findings.append({
                "url": form["action"],
                "issue": f"Potential reflected XSS in field '{field['name']}'",
                "severity": "High",
            })
        elif outcome == "blocked":
            findings.append({
                "url": form["action"],
                "issue": f"Could not test field '{field['name']}' (request blocked)",
                "severity": "Info",
            })
    return findings