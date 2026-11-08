from urllib.parse import urlparse
from scanner.config import ALLOWED_HOSTS, FORM_SKIP_WORDS


def host_allowed(url):
    """True only if the URL's host is on the allow-list."""
    return urlparse(url).hostname in ALLOWED_HOSTS


def form_is_safe_to_test(form):
    """True if the form's action doesn't look like it changes important state."""
    action = form["action"].lower()
    return not any(word in action for word in FORM_SKIP_WORDS)