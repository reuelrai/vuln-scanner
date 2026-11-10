from datetime import datetime
from urllib.parse import urlparse

import requests

from scanner.config import ALLOWED_HOSTS
from scanner.crawler import crawl
from scanner.errors import ScanError
from scanner.report import save_json
from scanner.safety import host_allowed, form_is_safe_to_test
from scanner.session import make_session
from scanner.checks.xss import check_reflected_xss
from scanner.checks.sqli import check_sqli_errors


def validate_target(target, start_path="/"):
    """Raise ScanError unless the target is a valid, approved URL."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScanError("Target must be a full URL starting with http:// or https://")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ScanError(
            f"{parsed.hostname} is not on the approved list (ALLOWED_HOSTS in scanner/config.py)"
        )
    if not start_path.startswith("/") or start_path.startswith("//"):
        raise ScanError("start_path must begin with a single '/'")


def run_active_checks(session, forms):
    findings = []

    print("\n--- Active checks ---")
    for form in forms:
        if not host_allowed(form["action"]):
            print("Skipped (host not on allow-list):", form["action"])
            continue
        if not form_is_safe_to_test(form):
            print("Skipped (risky form):", form["action"])
            continue
        if form["method"] != "get":
            print("Skipped (POST not supported yet):", form["action"])
            continue

        print("Testing: GET", form["action"])
        new = check_reflected_xss(session, form) + check_sqli_errors(session, form)
        print("   findings:", len(new))
        findings.extend(new)

    return findings


def run_scan(target, start_path="/", dvwa_login=False, active=False, save=True):
    """Run a full scan and return everything it found as a dictionary."""
    validate_target(target, start_path)

    started = datetime.now()

    try:
        session = make_session(target, dvwa_login)
        print("Session ready.\n")

        visited, findings, forms = crawl(session, target, start_path)

        if active:
            findings.extend(run_active_checks(session, forms))
        else:
            print("\nActive checks are OFF for this scan.")
    except requests.RequestException as error:
        raise ScanError(f"Could not reach {target}: {error}") from error

    saved_to = None
    if save:
        saved_to = save_json(target, active, visited, findings, forms, started)

    return {
        "target": target,
        "started": started,
        "visited": visited,
        "findings": findings,
        "forms": forms,
        "saved_to": saved_to,
    }