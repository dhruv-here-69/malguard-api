from fastapi import FastAPI, UploadFile, File, Form
from analyzer import (
    analyze_apk,
    analyze_exe,
    analyze_generic_file
)

import tempfile
import os
import re
import socket
import ipaddress
import requests
from urllib.parse import urlparse


app = FastAPI(title="MalGuard API")


@app.get("/")
def home():
    return {
        "status": "MalGuard Running"
    }


# ==========================
# FILE ROUTER
# ==========================

def analyze_by_extension(path: str, extension: str):
    if extension == ".apk":
        return analyze_apk(path)

    if extension == ".exe":
        return analyze_exe(path)

    return analyze_generic_file(path)


# ==========================
# URL SAFETY ANALYZER
# ==========================

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


def get_risk_level(score: int):
    if score < 30:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    elif score < 85:
        return "HIGH"
    return "CRITICAL"


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


def analyze_url_safety(url: str):
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
            "category": "Invalid or suspicious URL scheme",
            "url": url,
            "domain": None,
            "findings": ["URL does not use HTTP/HTTPS"],
            "redirect_info": {},
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
            "category": "Malformed URL",
            "url": url,
            "domain": None,
            "findings": ["No valid domain found"],
            "redirect_info": {},
            "recommendation": "Do not open this URL."
        }

    if is_private_or_internal_host(domain):
        return {
            "scan_type": "url",
            "file_type": "url",
            "sha256": None,
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "category": "Blocked internal/private URL",
            "url": url,
            "domain": domain,
            "findings": ["URL resolves to private/internal infrastructure"],
            "redirect_info": {},
            "recommendation": "Block this URL. Internal/private URL scanning is not allowed."
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

    if "@" in url:
        score += 25
        findings.append("URL contains @ symbol, commonly used in deception")

    if re.search(r"%[0-9a-fA-F]{2}", url):
        score += 10
        findings.append("URL contains encoded characters")

    redirect_info = check_redirects(url)

    if redirect_info.get("redirect_count", 0) >= 3:
        score += 20
        findings.append("Multiple redirects detected")

    if redirect_info.get("final_url") and redirect_info["final_url"] != url:
        findings.append("URL redirects to another location")

    score = min(score, 100)
    risk_level = get_risk_level(score)

    if score >= 85:
        category = "Critical phishing or malicious URL"
    elif score >= 60:
        category = "Likely phishing or malicious URL"
    elif score >= 30:
        category = "Suspicious URL"
    else:
        category = "Likely benign URL"

    if risk_level in ["HIGH", "CRITICAL"]:
        recommendation = "Do not open this URL. Block it and investigate the domain."
    elif risk_level == "MEDIUM":
        recommendation = "Open only in an isolated browser or sandbox. Monitor redirects and credential prompts."
    else:
        recommendation = "No strong malicious indicators found. Continue normal monitoring."

    if not findings:
        findings.append("No strong malicious URL indicators detected")

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
        "recommendation": recommendation
    }


# ==========================
# MAIN SCAN ENDPOINT
# ==========================

@app.post("/scan")
async def scan(
    file: UploadFile = File(None),
    url: str = Form(None)
):

    # ==========================
    # URL SAFETY SCAN
    # ==========================
    if url:
        result = analyze_url_safety(url)

        return {
            "status": "success",
            "source": "url",
            "filename": url,
            "submitted_url": url,
            "result": result
        }

    # ==========================
    # FILE SCAN
    # ==========================
    if file:
        extension = os.path.splitext(file.filename)[1].lower()

        if not extension:
            extension = ".bin"

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension
        ) as temp:
            content = await file.read()
            temp.write(content)
            path = temp.name

        try:
            result = analyze_by_extension(path, extension)

            return {
                "status": "success",
                "source": "file",
                "filename": file.filename,
                "result": result
            }

        finally:
            if os.path.exists(path):
                os.remove(path)

    return {
        "status": "error",
        "message": "Provide either a file or a URL."
    }
