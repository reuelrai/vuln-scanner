import requests

url = "https://quotes.toscrape.com"
response = requests.get(url)

important_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]

for header in important_headers:
    if header in response.headers:
        print("OK     :", header)
    else:
        print("MISSING:", header)