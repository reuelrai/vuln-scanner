from scanner.config import IMPORTANT_HEADERS


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