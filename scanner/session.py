import requests
from bs4 import BeautifulSoup
from scanner.errors import ScanError


def make_session(target, dvwa_login=False, level="low"):
    """Return a requests session. Logs in to DVWA first if dvwa_login is True."""
    session = requests.Session()

    if not dvwa_login:
        return session

    base = target.rstrip("/")

    page = session.get(base + "/login.php")
    soup = BeautifulSoup(page.text, "html.parser")
    token_field = soup.find("input", {"name": "user_token"})
    if token_field is None:
        raise ScanError("No DVWA login form found. Is DVWA running at " + base + "?")

    result = session.post(base + "/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token_field["value"],
    })
    if "Logout" not in result.text:
        raise ScanError("DVWA login failed. Did you create the database at /setup.php?")

    # change the existing 'security' cookie(s) instead of adding another
    for cookie in session.cookies:
        if cookie.name == "security":
            cookie.value = level

    # verify: ask the server what level it thinks we're at
    home = session.get(base + "/index.php")
    if f"<em>Security Level:</em> {level}" not in home.text:
        raise ScanError(f"Could not set security level to {level}")

    return session