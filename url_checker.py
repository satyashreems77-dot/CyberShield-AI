import re
from urllib.parse import urlparse


def check_url(url):
    warnings = []
    score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # No HTTPS
        if parsed.scheme != "https":
            score += 15
            warnings.append("The website does not use HTTPS.")

        # IP address instead of normal domain
        if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
            score += 30
            warnings.append("The link uses an IP address instead of a normal domain.")

        # Suspicious words in domain
        suspicious_words = [
            "login", "verify", "secure",
            "update", "account", "claim",
            "free", "winner"
        ]

        if any(word in domain for word in suspicious_words):
            score += 15
            warnings.append("The domain contains words commonly used in phishing links.")

        # Very long URL
        if len(url) > 100:
            score += 10
            warnings.append("The URL is unusually long.")

        score = min(score, 100)

    except Exception:
        score = 30
        warnings.append("The URL format could not be analyzed properly.")

    return {
        "score": score,
        "warnings": warnings
    }