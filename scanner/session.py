import requests
from bs4 import BeautifulSoup
from scanner.config import TARGET, USE_DVWA_LOGIN


def make_session(level="low"):
    """Return a requests session. Logs in to DVWA first if USE_DVWA_LOGIN is on."""
    session = requests.Session()

    if not USE_DVWA_LOGIN:
        return session

    page = session.get(TARGET + "/login.php")
    soup = BeautifulSoup(page.text, "html.parser")
    token = soup.find("input", {"name": "user_token"})["value"]

    result = session.post(TARGET + "/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token,
    })
    if "Logout" not in result.text:
        raise SystemExit("DVWA login failed. Is DVWA running and the database created?")

    # change the existing 'security' cookie(s) instead of adding another
    for cookie in session.cookies:
        if cookie.name == "security":
            cookie.value = level

    # verify: ask the server what level it thinks we're at
    home = session.get(TARGET + "/index.php")
    if f"<em>Security Level:</em> {level}" not in home.text:
        raise SystemExit(f"Could not set security level to {level}")

    return session