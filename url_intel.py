import os
import re
import socket
import ipaddress
import requests
import whois

from datetime import datetime, timezone
from urllib.parse import urlparse


GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")


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
    "reset",
    "loan",
    "cash",
    "reward",
    "prize"
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


def get_risk_level(score: int):
    if score < 30:
        return "LOW"

    if score < 60:
        return "MEDIUM"

    if score < 85:
        return "HIGH"

    return "CRITICAL"


def normalize_url(url: str):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def is_ip_address(value: str):
    try:
        ipaddress.ip_address(value)
        return True

    except Exception:
        return False


def domain_resolves(domain: str):
    try:
        socket.gethostbyname(domain)
        return True

    except Exception:
        return False


def is_private_or_internal_host(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        ip_obj = ipaddress.ip_address(ip)

        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )

    except Exception:
        return False


def check_redirects(url: str):
    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 MalGuardAI URL Scanner"
            }
        )

        return {
            "final_url": response.url,
            "redirect_count": len(response.history),
            "redirect_chain": [r.url for r in response.history],
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


def check_google_safe_browsing(url: str):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {
            "enabled": False,
            "safe_browsing_hit": False,
            "threats": []
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "malguard-ai",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10
        )

        data = response.json()
        matches = data.get("matches", [])

        return {
            "enabled": True,
            "safe_browsing_hit": len(matches) > 0,
            "threats": matches
        }

    except Exception as e:
        return {
            "enabled": True,
            "safe_browsing_hit": False,
            "threats": [],
            "error": str(e)
        }


def get_domain_age(domain: str):
    try:
        info = whois.whois(domain)

        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {
                "available": False,
                "domain_age_days": None,
                "creation_date": None,
                "error": "Creation date not available"
            }

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(timezone.utc)

        age_days = (now - creation_date).days

        return {
            "available": True,
            "domain_age_days": age_days,
            "creation_date": creation_date.isoformat()
        }

    except Exception as e:
        return {
            "available": False,
            "domain_age_days": None,
            "creation_date": None,
            "error": str(e)
        }


def analyze_url_safety(raw_url: str):
    url = normalize_url(raw_url)

    score = 0
    findings = []

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        return {
            "scan_type": "url",
            "file_type": "url",
            "sha256": None,
            "risk_score": 80,
            "risk_level": "HIGH",
            "category": "Suspicious URL",
            "url": url,
            "domain": None,
            "findings": [
                "URL does not use HTTP/HTTPS"
            ],
            "redirect_info": {},
            "safe_browsing": {},
            "whois": {},
            "recommendation": "Do not open this URL."
        }

    domain = parsed.hostname.lower() if parsed.hostname else None

    if not domain:
        return {
            "scan_type": "url",
            "file_type": "url",
            "sha256": None,
            "risk_score": 80,
            "risk_level": "HIGH",
            "category": "Suspicious URL",
            "url": url,
            "domain": None,
            "findings": [
                "No valid domain found"
            ],
            "redirect_info": {},
            "safe_browsing": {},
            "whois": {},
            "recommendation": "Do not open this URL."
        }

    if is_private_or_internal_host(domain):
        return {
            "scan_type": "url",
            "file_type": "url",
            "sha256": None,
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "category": "Command & Control Infrastructure",
            "url": url,
            "domain": domain,
            "findings": [
                "URL resolves to private/internal infrastructure"
            ],
            "redirect_info": {},
            "safe_browsing": {},
            "whois": {},
            "recommendation": "Block this URL. Internal/private URL scanning is not allowed."
        }

    path = parsed.path.lower()

    domain_parts = domain.split(".")
    domain_name = domain_parts[0] if domain_parts else ""

    if parsed.scheme == "http":
        score += 15
        findings.append("URL does not use HTTPS")

    if is_ip_address(domain):
        score += 35
        findings.append("URL uses raw IP address instead of domain")

    domain_is_resolvable = domain_resolves(domain)

    if not domain_is_resolvable:
        score += 20
        findings.append("Domain does not resolve")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 8
            findings.append(
                f"Suspicious keyword detected: {keyword}"
            )

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            findings.append(
                f"Suspicious top-level domain detected: {tld}"
            )

    if len(domain_name) <= 5:
        score += 15
        findings.append("Short or random-looking domain name")

    if len(url) > 120:
        score += 10
        findings.append("URL is unusually long")

    if domain.count(".") >= 3:
        score += 10
        findings.append("URL contains multiple subdomains")

    if "@" in url:
        score += 25
        findings.append(
            "URL contains @ symbol, commonly used in deception"
        )

    if re.search(r"%[0-9a-fA-F]{2}", url):
        score += 10
        findings.append("URL contains encoded characters")

    if re.search(r"[a-z0-9]{3,}[-_][a-z0-9]{5,}", path):
        score += 20
        findings.append("Random campaign-style URL path detected")

    if re.search(r"\d{5,}", path):
        score += 15
        findings.append("Long numeric token detected in URL path")

    if re.search(r"[a-z]+\d+|\d+[a-z]+", path):
        score += 10
        findings.append("Mixed alphanumeric tracking token detected")

    if domain.endswith(".xyz") and len(path) > 5:
        score += 20
        findings.append("Suspicious .xyz campaign-style link")

    redirect_info = check_redirects(url)

    if redirect_info.get("redirect_count", 0) >= 3:
        score += 20
        findings.append("Multiple redirects detected")

    if (
        redirect_info.get("final_url")
        and redirect_info["final_url"] != url
    ):
        findings.append("URL redirects to another location")

    whois_info = get_domain_age(domain)

    if whois_info.get("available"):
        age_days = whois_info.get("domain_age_days")

        if age_days is not None:
            if age_days <= 7:
                score += 30
                findings.append(
                    "Very newly registered domain detected"
                )

            elif age_days <= 30:
                score += 20
                findings.append(
                    "Recently registered domain detected"
                )

            elif age_days <= 90:
                score += 10
                findings.append("Young domain detected")

    else:
        findings.append("WHOIS domain age unavailable")

    safe_browsing = check_google_safe_browsing(url)

    if safe_browsing.get("safe_browsing_hit"):
        score += 60
        findings.append("Google Safe Browsing flagged this URL")

    if not domain_is_resolvable and score >= 60:
        score = 50
        findings.append(
            "Risk capped because domain is unreachable; no live malicious content confirmed"
        )

    score = min(int(score), 100)

    risk_level = get_risk_level(score)

    if safe_browsing.get("safe_browsing_hit"):
        category = "Phishing URL"

    elif score >= 85:
        category = "Phishing URL"

    elif score >= 60:
        category = "Phishing URL"

    elif score >= 30:
        category = "Suspicious URL"

    else:
        category = "Benign URL"

    if not findings:
        findings.append("No strong malicious URL indicators detected")

    if risk_level in ["HIGH", "CRITICAL"]:
        recommendation = (
            "Do not open this URL. Block it and investigate the domain."
        )

    elif risk_level == "MEDIUM":
        recommendation = (
            "Open only in an isolated browser or sandbox. "
            "Validate the source before proceeding."
        )

    else:
        recommendation = (
            "No strong malicious indicators found. "
            "Continue normal monitoring."
        )

    return {
        "scan_type": "url",
        "file_type": "url",
        "sha256": None,
        "risk_score": score,
        "risk_level": risk_level,
        "category": category,
        "url": url,
        "domain": domain,
        "findings": findings,
        "redirect_info": redirect_info,
        "safe_browsing": safe_browsing,
        "whois": whois_info,
        "recommendation": recommendation
    }
