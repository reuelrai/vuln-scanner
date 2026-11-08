# Web Vulnerability Scanner (working name)

A Python scanner that crawls a website, finds its forms, and checks for
common web vulnerabilities. Built as a final year project.

> **Only scan sites you own or have written permission to test.**
> Active checks send test input to forms. Use them on local practice
> targets like DVWA, never on someone else's site.

## What it checks

| Check | Type | Notes |
|---|---|---|
| Missing security headers | Passive | CSP, X-Frame-Options, X-Content-Type-Options, HSTS |
| HTTPS redirected to HTTP | Passive | |
| Reflected XSS | Active | GET forms only |
| SQL injection (error-based) | Active | GET forms only |

Findings are labeled "potential": they show that something looks wrong,
not proof of exploitability.

## Setup

```
python -m venv venv
venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```

## Try it on DVWA (a deliberately vulnerable practice app)

1. Start DVWA (requires Docker):
   ```
   docker run --rm -it --name dvwa -p 127.0.0.1:8080:80 vulnerables/web-dvwa
   ```
2. Open http://localhost:8080/setup.php and click **Create / Reset Database**
   (needed after every restart).
3. Run the scanner:
   ```
   python main.py
   ```
4. Results print to the terminal and are saved as JSON in `results/`.
5. Stop DVWA with `Ctrl+C` or `docker stop dvwa`.

## Configuration

All settings are in `scanner/config.py`: target URL, page limit, which
links and forms to skip, and the active-check safety switches
(`ACTIVE_CHECKS`, `ALLOWED_HOSTS`). Set `USE_DVWA_LOGIN = False` when
scanning anything other than DVWA.

## Project layout

```
main.py            run the scanner
scanner/           the scanner engine
    config.py      settings
    session.py     login and session setup
    crawler.py     page crawler and form extraction
    safety.py      allow-list and risky-form rules
    report.py      console report and JSON output
    checks/        one file per check (headers, xss, sqli)
scratch/           early experiments
results/           saved scans (not committed)
```

## Known limitations

- Active checks handle GET forms only (POST support is planned)
- Blind SQL injection is not detected (no visible error to read)
- DOM-based XSS is not detected (no JavaScript is executed)