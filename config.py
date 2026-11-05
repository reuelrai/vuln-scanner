# ---------- Settings ----------
TARGET = "http://localhost:8080"
START_PATH = "/index.php"
USE_DVWA_LOGIN = True                   # True only when scanning DVWA
MAX_PAGES = 40
SKIP_WORDS = ["logout", "setup", "vote", "delete", "remove", "submit"]
IMPORTANT_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]