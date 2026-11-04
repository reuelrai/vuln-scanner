import requests
from bs4 import BeautifulSoup

base = "http://localhost:8080"
session = requests.Session()

# Step 1: load the login page and grab the hidden token
page = session.get(base + "/login.php")
soup = BeautifulSoup(page.text, "html.parser")
token = soup.find("input", {"name": "user_token"})["value"]

# Step 2: submit the login form with that token
data = {
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": token,
}
result = session.post(base + "/login.php", data=data)
print("Landed on:", result.url)
print("Redirects:", [r.url for r in result.history])
print("Page title:", BeautifulSoup(result.text, "html.parser").title)
print("Mentions 'failed':", "failed" in result.text.lower())
print("Mentions 'setup':", "setup" in result.url.lower())

# Step 3: did it work?
print("Logged in:", "Logout" in result.text)

# Step 4: set the difficulty to Low, then peek at a vulnerable page
session.cookies.set("security", "low")
xss_page = session.get(base + "/vulnerabilities/xss_r/")
print("XSS page status:", xss_page.status_code)
print("Has the form:", "What's your name?" in xss_page.text)