import os
import re
import yara
import pefile
import hashlib
from androguard.misc import AnalyzeAPK


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

        urls = re.findall(
            r'https?://[^\s\'"<>]+',
            text
        )

        return list(set(urls))

    except Exception:
        return []


def yara_scan(path):

    try:

        rules = yara.compile(filepath=RULES_FILE)

        matches = rules.match(path)

        return [match.rule for match in matches]

    except Exception:
        return []


# ==========================
# GENERIC FILE ANALYSIS
# ==========================

def analyze_generic_file(path):

    yara_matches = yara_scan(path)

    urls = extract_urls(path)

    sha256 = calculate_sha256(path)

    risk_score = 0

    risk_score += len(yara_matches) * 40
    risk_score += len(urls) * 5

    risk_score = min(risk_score, 100)

    return {
        "file_type": "generic",
        "sha256": sha256,
        "urls": urls,
        "yara_matches": yara_matches,
        "risk_score": risk_score
    }


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

        found_permissions = []

        for permission in permissions:

            for danger in dangerous_permissions:

                if danger in permission:
                    found_permissions.append(danger)

        sha256 = calculate_sha256(path)

        permission_score = len(found_permissions) * 15
        yara_score = len(yara_matches) * 40

        risk_score = min(
            permission_score +
            yara_score,
            100
        )

        return {
            "file_type": "apk",
            "sha256": sha256,
            "app_name": a.get_app_name(),
            "package": a.get_package(),
            "permissions": permissions,
            "dangerous_permissions": found_permissions,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "yara_matches": yara_matches,
            "risk_score": risk_score
        }

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

                dll_name = entry.dll.decode(
                    errors="ignore"
                )

                dlls.append(dll_name)

                if dll_name.lower() in suspicious_dlls:

                    suspicious_dlls_found.append(
                        dll_name
                    )

                for imp in entry.imports:

                    if imp.name:

                        function_name = imp.name.decode(
                            errors="ignore"
                        )

                        if function_name in suspicious_functions:

                            suspicious_functions_found.append(
                                function_name
                            )

        sha256 = calculate_sha256(path)

        dll_score = len(
            suspicious_dlls_found
        ) * 10

        function_score = len(
            suspicious_functions_found
        ) * 20

        yara_score = len(
            yara_matches
        ) * 40

        risk_score = min(
            dll_score +
            function_score +
            yara_score,
            100
        )

        return {
            "file_type": "exe",
            "sha256": sha256,
            "imports": dlls,
            "suspicious_imports": suspicious_dlls_found,
            "suspicious_functions": suspicious_functions_found,
            "yara_matches": yara_matches,
            "risk_score": risk_score
        }

    except Exception as e:

        return {
            "file_type": "exe",
            "error": str(e)
        }
