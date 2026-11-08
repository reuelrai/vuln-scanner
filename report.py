import json
import os
from datetime import datetime
from config import TARGET, ACTIVE_CHECKS, RESULTS_DIR


def print_report(visited, all_findings, all_forms):
    print("\n--- SCAN REPORT ---")
    print("Pages scanned:", len(visited))

    grouped = {}
    for finding in all_findings:
        key = (finding["severity"], finding["issue"])
        grouped.setdefault(key, []).append(finding["url"])

    for (severity, issue), urls in grouped.items():
        print(f"[{severity}] {issue}  (on {len(urls)} pages)")
        if len(urls) <= 3:
            for u in urls:
                print("      ->", u)

    print("\nForms found:", len(all_forms))
    for f in all_forms:
        names = [i["name"] for i in f["inputs"]]
        print(f"  {f['method'].upper()} {f['action']}  inputs: {names}")


def save_json(visited, all_findings, all_forms, started):
    """Write the scan results to results/scan_<timestamp>.json. Returns the file path."""
    finished = datetime.now()

    # count findings per severity
    summary = {}
    for finding in all_findings:
        severity = finding["severity"]
        summary[severity] = summary.get(severity, 0) + 1

    data = {
        "scan": {
            "target": TARGET,
            "started": started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"),
            "active_checks": ACTIVE_CHECKS,
            "pages_scanned": len(visited),
        },
        "summary": summary,
        "findings": all_findings,
        "forms": all_forms,
        "pages": sorted(visited),          # a set can't be saved as JSON, so make it a sorted list
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    filename = "scan_" + started.strftime("%Y-%m-%d_%H%M%S") + ".json"
    path = os.path.join(RESULTS_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return path