from datetime import datetime
from session import make_session
from crawler import crawl
from report import print_report, save_json
from config import ACTIVE_CHECKS, SAVE_RESULTS
from safety import host_allowed, form_is_safe_to_test
from checks.xss import check_reflected_xss
from checks.sqli import check_sqli_errors


def run_active_checks(session, forms):
    findings = []

    if not ACTIVE_CHECKS:
        print("\nActive checks are OFF (ACTIVE_CHECKS in config.py).")
        return findings

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


def main():
    started = datetime.now()

    session = make_session()
    print("Session ready.\n")

    visited, all_findings, all_forms = crawl(session)
    all_findings.extend(run_active_checks(session, all_forms))

    print_report(visited, all_findings, all_forms)

    if SAVE_RESULTS:
        path = save_json(visited, all_findings, all_forms, started)
        print("\nSaved results to", path)


if __name__ == "__main__":
    main()