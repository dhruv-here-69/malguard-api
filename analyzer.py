import pefile
from androguard.misc import AnalyzeAPK


def analyze_apk(path):

    try:
        a, d, dx = AnalyzeAPK(path)

        permissions = a.get_permissions()

        dangerous = [
            "READ_SMS",
            "SEND_SMS",
            "RECEIVE_SMS",
            "READ_CONTACTS",
            "REQUEST_INSTALL_PACKAGES",
            "SYSTEM_ALERT_WINDOW",
            "READ_CALL_LOG",
            "WRITE_CALL_LOG"
        ]

        dangerous_found = []

        for p in permissions:
            for d_perm in dangerous:
                if d_perm in p:
                    dangerous_found.append(d_perm)

        return {
            "file_type": "apk",
            "package": a.get_package(),
            "app_name": a.get_app_name(),
            "permissions": permissions,
            "dangerous_permissions": dangerous_found,
            "risk_score": min(len(dangerous_found) * 15, 100)
        }

    except Exception as e:
        return {
            "error": str(e)
        }


def analyze_exe(path):

    try:
        pe = pefile.PE(path)

        dlls = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dlls.append(entry.dll.decode())

        suspicious_dlls = [
            "wininet.dll",
            "ws2_32.dll",
            "urlmon.dll",
            "crypt32.dll",
            "advapi32.dll"
        ]

        found = []

        for dll in dlls:
            if dll.lower() in suspicious_dlls:
                found.append(dll)

        return {
            "file_type": "exe",
            "imports": dlls,
            "suspicious_imports": found,
            "risk_score": min(len(found) * 20, 100)
        }

    except Exception as e:
        return {
            "error": str(e)
        }
