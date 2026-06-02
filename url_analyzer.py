import re
import socket
import ipaddress
from urllib.parse import urlparse
import requests


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
    "signin",
    "password",
    "otp",
    "wallet",
    "payment",
    "kyc",
    "refund",
    "claim",
    "bonus",
    "free",
    "gift",
    "reset"
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".buzz",
    ".work",
    ".zip"
]


def get_risk_level(score):
    if score < 30:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    elif score < 85:
        return "HIGH"
    return "CRITICAL"


def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False


def domain_resolves(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def check_redirects(url):
    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 MalGuardAI URL Scanner"
            }
        )

        history = [r.url for r in response.history]

        return {
            "final_url": response.url,
            "redirect_count": len(history),
            "redirect_chain": history,
            "status_code": response.status_code
        }

    except Exception as e:
        return {
            "final_url": None,
            "redirect_count": 0,
            "redirect_chain": [],
            "status_code": None,
            "error": str(e)
        }


def analyze_url(url):
    score = 0
    findings = []

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        return {
            "scan_type": "url",
            "url": url,
            "risk_score": 70,
            "risk_level": "HIGH",
            "category": "Invalid or suspicious URL scheme",
            "findings": ["URL does not use HTTP/HTTPS"],
            "recommendation": "Do not open this URL."
        }

    domain = parsed.netloc.lower()

    if not domain:
        return {
            "scan_type": "url",
            "url": url,
            "risk_score": 80,
            "risk_level": "HIGH",
            "category": "Malformed URL",
            "findings": ["No valid domain found"],
            "recommendation": "Do not open this URL."
        }

    if parsed.scheme == "http":
        score += 15
        findings.append("URL does not use HTTPS")

    if is_ip_address(domain):
        score += 35
        findings.append("URL uses raw IP address instead of domain")

    if not domain_resolves(domain):
        score += 30
        findings.append("Domain does not resolve")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 8
            findings.append(f"Suspicious keyword detected: {keyword}")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            findings.append(f"Suspicious top-level domain detected: {tld}")

    if len(url) > 120:
        score += 10
        findings.append("URL is unusually long")

    if domain.count(".") >= 3:
        score += 10
        findings.append("URL contains multiple subdomains")

    redirect_info = check_redirects(url)

    if redirect_info.get("redirect_count", 0) >= 3:
        score += 20
        findings.append("Multiple redirects detected")

    if redirect_info.get("final_url") and redirect_info["final_url"] != url:
        findings.append("URL redirects to another location")

    score = min(score, 100)
    risk_level = get_risk_level(score)

    if score >= 75:
        category = "Likely phishing or malicious URL"
    elif score >= 50:
        category = "Suspicious URL"
    elif score >= 25:
        category = "Low-confidence suspicious URL"
    else:
        category = "Likely benign URL"

    if risk_level in ["HIGH", "CRITICAL"]:
        recommendation = "Do not open this URL. Block it and investigate the domain."
    elif risk_level == "MEDIUM":
        recommendation = "Open only in isolated browser or sandbox. Monitor for redirects and credential prompts."
    else:
        recommendation = "No strong malicious indicators found, but continue normal monitoring."

    return {
        "scan_type": "url",
        "url": url,
        "domain": domain,
        "risk_score": score,
        "risk_level": risk_level,
        "category": category,
        "findings": findings,
        "redirect_info": redirect_info,
        "recommendation": recommendation
    }
