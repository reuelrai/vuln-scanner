import json
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException

from scanner.config import RESULTS_DIR

app = FastAPI(title="Vulnerability Scanner API")

from fastapi.responses import RedirectResponse

SCAN_ID_PATTERN = re.compile(r"scan_\d{4}-\d{2}-\d{2}_\d{6}")


def read_scan(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/scans")
def list_scans():
    """List saved scans, newest first, with a short summary of each."""
    folder = Path(RESULTS_DIR)
    if not folder.exists():
        return []

    scans = []
    for path in sorted(folder.glob("scan_*.json"), reverse=True):
        try:
            data = read_scan(path)
            scans.append({
                "id": path.stem,
                "target": data["scan"]["target"],
                "started": data["scan"]["started"],
                "pages_scanned": data["scan"]["pages_scanned"],
                "summary": data["summary"],
            })
        except (json.JSONDecodeError, KeyError):
            continue        # skip half-written or damaged files instead of crashing

    return scans


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    """Return the full results of one saved scan."""
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    path = Path(RESULTS_DIR) / (scan_id + ".json")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    return read_scan(path)

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")