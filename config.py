# ---------- Target ----------
TARGET = "http://localhost:8080"
START_PATH = "/index.php"
USE_DVWA_LOGIN = True                   # True only when scanning DVWA

# ---------- Crawling ----------
MAX_PAGES = 40
SKIP_WORDS = ["logout", "setup", "vote", "delete", "remove", "submit"]

# ---------- Passive checks ----------
IMPORTANT_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]

# ---------- Active checks (these SEND test input) ----------
ACTIVE_CHECKS = True                    # set to False when scanning anything else
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
FORM_SKIP_WORDS = ["csrf", "ids_log", "brute", "security", "setup", "logout", "exec", "upload", "xss_s"]
SKIP_FIELD_TYPES = ["hidden", "submit", "button", "password", "file", "checkbox", "radio"]

# ---------- Saving results ----------
SAVE_RESULTS = True
RESULTS_DIR = "results"