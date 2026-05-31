import re
import socket
import requests
from urllib.parse import urlparse
import time


# ==========================
# BASIC URL FEATURES
# ==========================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "bank",
    "account",
    "password",
    "signin",
    "confirm"
]


# ==========================
# EXTRACT DOMAIN INFO
# ==========================

def extract_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return None


# ==========================
# DNS CHECK
# ==========================

def is_ip_based_domain(domain):
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain or ""))


def domain_resolves(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


# ==========================
# URL SCORING ENGINE
# ==========================

def analyze_url(url):

    score = 0
    signals = []

    domain = extract_domain(url)

    if not domain:
        return {
            "url": url,
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "signals": ["invalid_url"]
        }

    domain_lower = domain.lower()

    # ==========================
    # IP BASED DOMAIN (VERY HIGH RISK)
    # ==========================
    if is_ip_based_domain(domain_lower):
        score += 40
        signals.append("IP-based domain")

    # ==========================
    # SUSPICIOUS KEYWORDS
    # ==========================
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url.lower():
            score += 10
            signals.append(f"suspicious keyword: {kw}")

    # ==========================
    # HTTPS CHECK
    # ==========================
    if not url.startswith("https"):
        score += 15
        signals.append("no HTTPS")

    # ==========================
    # DOMAIN RESOLUTION
    # ==========================
    if not domain_resolves(domain):
        score += 25
        signals.append("domain does not resolve")

    # ==========================
    # LENGTH ANOMALY
    # ==========================
    if len(url) > 100:
        score += 10
        signals.append("abnormally long URL")

    # ==========================
    # FINAL SCORE
    # ==========================
    score = min(score, 100)

    if score < 30:
        level = "LOW"
    elif score < 60:
        level = "MEDIUM"
    elif score < 85:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "url": url,
        "domain": domain,
        "risk_score": score,
        "risk_level": level,
        "signals": signals
    }


# ==========================
# BULK ANALYSIS
# ==========================

def analyze_urls(url_list):

    results = []

    for url in url_list:
        results.append(analyze_url(url))

    # overall risk aggregation
    if results:
        avg_score = sum(r["risk_score"] for r in results) / len(results)
    else:
        avg_score = 0

    return {
        "urls": results,
        "average_risk": round(avg_score, 2)
    }
