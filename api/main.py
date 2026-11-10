import json
import re
import threading
import traceback
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from scanner.config import RESULTS_DIR, ACTIVE_CHECKS
from scanner.errors import ScanError
from scanner.runner import run_scan, validate_target

app = FastAPI(title="Vulnerability Scanner API")

SCAN_ID_PATTERN = re.compile(r"scan_\d{4}-\d{2}-\d{2}_\d{6}")

jobs = {}                        # job_id -> info about a scan started through the API
scan_lock = threading.Lock()     # only one scan at a time


class ScanRequest(BaseModel):
    target: str
    start_path: str = "/"
    dvwa_login: bool = False
    active: bool = False


def read_scan(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_job(job_id, request, active):
    """Runs in the background. Always releases the lock when done."""
    job = jobs[job_id]
    try:
        result = run_scan(
            request.target,
            request.start_path,
            dvwa_login=request.dvwa_login,
            active=active,
            save=True,
        )
        job["status"] = "finished"
        job["scan_id"] = Path(result["saved_to"]).stem
    except ScanError as error:
        job["status"] = "failed"
        job["error"] = str(error)
    except Exception as error:
        traceback.print_exc()                       # full details go to the server console
        job["status"] = "failed"
        job["error"] = "Unexpected error: " + type(error).__name__
    finally:
        job["finished"] = datetime.now().isoformat(timespec="seconds")
        scan_lock.release()


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scans", status_code=202)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a scan in the background. Returns a job_id to check progress."""
    try:
        validate_target(request.target, request.start_path)
    except ScanError as error:
        raise HTTPException(status_code=400, detail=str(error))

    if not scan_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="A scan is already running")

    active = request.active and ACTIVE_CHECKS       # config.py keeps the final say

    job_id = uuid.uuid4().hex[:12]
    jobs[job_id] = {
        "status": "running",
        "target": request.target,
        "active": active,
        "started": datetime.now().isoformat(timespec="seconds"),
    }
    background_tasks.add_task(run_job, job_id, request, active)

    return {"job_id": job_id, "status": "running", "active": active}


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


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
            continue

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