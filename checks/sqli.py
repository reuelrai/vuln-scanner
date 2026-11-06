from config import SKIP_FIELD_TYPES
from checks.xss import get_hidden_values

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg_query()",
    "syntax error at or near",
]


def send_value(session, form, field_name, value):
    """Submit the form with `value` in one field. Returns the response text, lowercased."""
    params = get_hidden_values(session, form["page"])     # fresh token every time
    for field in form["inputs"]:
        params.setdefault(field["name"], "1")             # fill the other fields
    params[field_name] = value
    return session.get(form["action"], params=params).text.lower()


def check_sqli_errors(session, form):
    """Look for database error messages caused by a single quote. GET forms only."""
    findings = []

    if form["method"] != "get":
        return findings

    for field in form["inputs"]:
        if field["type"] in SKIP_FIELD_TYPES:
            continue

        baseline = send_value(session, form, field["name"], "1")    # normal input
        probe = send_value(session, form, field["name"], "1'")      # quote that can break a query

        for signature in SQL_ERRORS:
            if signature in probe and signature not in baseline:
                findings.append({
                    "url": form["action"],
                    "issue": f"Possible SQL injection (database error) in field '{field['name']}'",
                    "severity": "High",
                })
                break                                                # one finding per field is enough
    return findings