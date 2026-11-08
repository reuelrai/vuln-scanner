import requests

urls = [
    "https://quotes.toscrape.com/tag/change/page/1",
    "https://quotes.toscrape.com/tag/change/page/1/",
    "https://quotes.toscrape.com/author/Albert-Einstein",
    "https://quotes.toscrape.com/author/Albert-Einstein/",
]

for u in urls:
    r = requests.get(u)
    print(u)
    print("   status:", r.status_code)
    print("   final URL:", r.url)
    print("   redirects:", len(r.history))
    print("   HSTS:", r.headers.get("Strict-Transport-Security"))