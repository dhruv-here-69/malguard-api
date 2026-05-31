import pefile
from androguard.misc import AnalyzeAPK


# ==========================
# APK ANALYZER
# ==========================

def analyze_apk(path):

    try:
        a, d, dx = AnalyzeAPK(path)

        permissions = a.get_permissions()
        activities = a.get_activities()
        services = a.get_services()
        receivers = a.get_receivers()

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

        risk_score = min(len(found_permissions) * 15, 100)

        return {
            "file_type": "apk",
            "app_name": a.get_app_name(),
            "package": a.get_package(),
            "permissions": permissions,
            "dangerous_permissions": found_permissions,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "risk_score": risk_score
        }

    except Exception as e:
        return {
            "file_type": "apk",
            "error": str(e)
        }


# ==========================
# EXE ANALYZER
# ==========================

def analyze_exe(path):

    try:
        pe = pefile.PE(path)

        dlls = []
        suspicious_dlls_found = []
        suspicious_functions_found = []

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

                        function_name = imp.name.decode(
                            errors="ignore"
                        )

                        if function_name in suspicious_functions:
                            suspicious_functions_found.append(
                                function_name
                            )

        dll_score = len(suspicious_dlls_found) * 10
        function_score = len(suspicious_functions_found) * 20

        risk_score = min(dll_score + function_score, 100)

        return {
            "file_type": "exe",
            "imports": dlls,
            "suspicious_imports": suspicious_dlls_found,
            "suspicious_functions": suspicious_functions_found,
            "risk_score": risk_score
        }

    except Exception as e:
        return {
            "file_type": "exe",
            "error": str(e)
        }
