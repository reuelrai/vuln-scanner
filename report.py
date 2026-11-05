def print_report(visited, all_findings, all_forms):
    print("\n--- SCAN REPORT ---")
    print("Pages scanned:", len(visited))

    grouped = {}
    for finding in all_findings:
        key = (finding["severity"], finding["issue"])
        grouped.setdefault(key, []).append(finding["url"])

    for (severity, issue), urls in grouped.items():
        print(f"[{severity}] {issue}  (on {len(urls)} pages)")

    print("\nForms found:", len(all_forms))
    for f in all_forms:
        names = [i["name"] for i in f["inputs"]]
        print(f"  {f['method'].upper()} {f['action']}  inputs: {names}")