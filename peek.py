from session import make_session
from checks.xss import MARKER

session = make_session()
response = session.get(
    "http://localhost:8080/vulnerabilities/sqli/",
    params={"id": MARKER, "Submit": "test"},
)

for line in response.text.splitlines():
    if "zq7431" in line:
        print(line.strip())