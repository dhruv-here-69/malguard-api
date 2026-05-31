import os
import re
import yara
import pefile
import hashlib
from androguard.misc import AnalyzeAPK

from analysis.intelligence.ai_engine import classify_threat


# ==========================
# CONFIG
# ==========================

RULES_FILE = os.path.join(
    os.path.dirname(__file__),
    "rules",
    "basic.yar"
)


# ==========================
# HELPERS
# ==========================

def calculate_sha256(path):
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)

    return sha256.hexdigest()


def extract_urls(path):
    try:
        with open(path, "rb") as f:
            content = f.read()

        text = content.decode(errors="ignore")

        urls = re.findall(r'https?://[^\s\'"<>]+', text)

        return list(set(urls))

    except Exception:
        return []


def yara_scan(path):
    try:
        rules = yara.compile(filepath=RULES_FILE)
        matches = rules.match(path)
        return [m.rule for m in matches]
    except Exception:
        return []


# ==========================
# RESPONSE NORMALIZER
# ==========================

def build_response(file_type, sha256, risk_score, extra):

    if risk_score < 30:
        level = "LOW"
    elif risk_score < 60:
        level = "MEDIUM"
    elif risk_score < 85:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "file_type": file_type,
        "sha256": sha256,
        "risk_score": risk_score,
        "risk_level": level,
        "analysis": extra
    }


# ==========================
# GENERIC FILE ANALYSIS
# ==========================

def analyze_generic_file(path):

    sha256 = calculate_sha256(path)
    urls = extract_urls(path)
    yara_matches = yara_scan(path)

    ai_result = classify_threat(
        static={
            "analysis": {
                "dangerous_permissions": [],
                "suspicious_functions": [],
                "yara_matches": yara_matches,
                "urls": urls
            }
        },
        url_data=None,
        sandbox_data=None
    )

    return build_response(
        "generic",
        sha256,
        ai_result["risk_score"],
        {
            "urls": urls,
            "yara_matches": yara_matches,
            "ai_analysis": ai_result
        }
    )


# ==========================
# APK ANALYSIS
# ==========================

def analyze_apk(path):

    try:
        a, d, dx = AnalyzeAPK(path)

        permissions = a.get_permissions()
        activities = a.get_activities()
        services = a.get_services()
        receivers = a.get_receivers()

        yara_matches = yara_scan(path)

        dangerous_permissions = [
            "READ_SMS",
            "SEND_SMS",
            "RECEIVE_SMS",
            "READ_CONTACTS",
            "REQUEST_INSTALL_PACKAGES",
            "SYSTEM_ALERT_WINDOW",
            "READ_CALL_LOG",
            "WRITE_CALL_LOG",
            "RECEIVE_BOOT_COMPLETED",
            "ACCESS_FINE_LOCATION",
            "READ_PHONE_STATE",
            "BIND_ACCESSIBILITY_SERVICE"
        ]

        found_permissions = [
            d for p in permissions for d in dangerous_permissions if d in p
        ]

        sha256 = calculate_sha256(path)

        ai_result = classify_threat(
            static={
                "analysis": {
                    "dangerous_permissions": found_permissions,
                    "suspicious_functions": [],
                    "yara_matches": yara_matches,
                    "urls": []
                }
            },
            url_data=None,
            sandbox_data=None
        )

        return build_response(
            "apk",
            sha256,
            ai_result["risk_score"],
            {
                "app_name": a.get_app_name(),
                "package": a.get_package(),
                "permissions": permissions,
                "dangerous_permissions": found_permissions,
                "activities": activities,
                "services": services,
                "receivers": receivers,
                "yara_matches": yara_matches,
                "ai_analysis": ai_result
            }
        )

    except Exception as e:
        return {
            "file_type": "apk",
            "error": str(e)
        }


# ==========================
# EXE ANALYSIS
# ==========================

def analyze_exe(path):

    try:

        pe = pefile.PE(path)

        dlls = []
        suspicious_dlls_found = []
        suspicious_functions_found = []

        yara_matches = yara_scan(path)

        suspicious_dlls = [
            "wininet.dll",
            "ws2_32.dll",
            "urlmon.dll",
            "crypt32.dll",
            "advapi32.dll"
        ]

        suspicious_functions = [
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "InternetOpenA",
            "InternetOpenW",
            "InternetReadFile",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW"
        ]

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                dll_name = entry.dll.decode(errors="ignore")
                dlls.append(dll_name)

                if dll_name.lower() in suspicious_dlls:
                    suspicious_dlls_found.append(dll_name)

                for imp in entry.imports:

                    if imp.name:
                        fn = imp.name.decode(errors="ignore")

                        if fn in suspicious_functions:
                            suspicious_functions_found.append(fn)

        sha256 = calculate_sha256(path)

        ai_result = classify_threat(
            static={
                "analysis": {
                    "dangerous_permissions": [],
                    "suspicious_functions": suspicious_functions_found,
                    "yara_matches": yara_matches,
                    "urls": []
                }
            },
            url_data=None,
            sandbox_data=None
        )

        return build_response(
            "exe",
            sha256,
            ai_result["risk_score"],
            {
                "imports": dlls,
                "suspicious_imports": suspicious_dlls_found,
                "suspicious_functions": suspicious_functions_found,
                "yara_matches": yara_matches,
                "ai_analysis": ai_result
            }
        )

    except Exception as e:
        return {
            "file_type": "exe",
            "error": str(e)
        }
