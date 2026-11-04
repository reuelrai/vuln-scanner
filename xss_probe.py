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

    # change the existing 'security' cookie(s) instead of adding another
    for cookie in session.cookies:
        if cookie.name == "security":
            cookie.value = level

    # verify: ask the server what level it thinks we're at
    home = session.get(TARGET + "/index.php")
    if f"<em>Security Level:</em> {level}" not in home.text:
        raise SystemExit(f"Could not set security level to {level}")

    return session


def check_reflected_xss(session, form):
    """Test each field of a GET form with the marker. Returns a list of findings."""
    findings = []
    if form["method"] != "get":
        return findings                      # POST forms come later

    for field in form["inputs"]:
        # fill every field with harmless text, then put the marker in this one
        params = {i["name"]: "test" for i in form["inputs"]}
        params[field["name"]] = MARKER

        response = session.get(form["action"], params=params)

        if MARKER in response.text:          # came back unescaped
            findings.append({
                "url": form["action"],
                "issue": f"Potential reflected XSS in field '{field['name']}'",
                "severity": "High",
            })
    return findings


# a hand-made form, shaped like the ones our crawler produces
xss_form = {
    "page": TARGET + "/vulnerabilities/xss_r/",
    "action": TARGET + "/vulnerabilities/xss_r/",
    "method": "get",
    "inputs": [{"name": "name", "type": "text"}],
}

for level in ["low", "medium", "high", "impossible"]:
    session = make_session(level)
    response = session.get(xss_form["action"], params={"name": MARKER})
    text = response.text

    print(f"{level:11} | status {response.status_code}"
        f" | marker present: {'zq7431' in text}"
        f" | raw: {MARKER in text}"
        f" | token complaint: {'csrf token is incorrect' in text.lower()}")