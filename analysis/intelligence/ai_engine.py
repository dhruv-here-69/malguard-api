def classify_threat(static, url_data, sandbox_data):

    score = 0
    reasons = []
    attack_vectors = set()
    mitre = set()

    # =========================
    # APK SIGNALS
    # =========================

    apk_data = static.get("analysis", {})

    dangerous_perms = apk_data.get("dangerous_permissions", [])

    if dangerous_perms:
        score += len(dangerous_perms) * 12
        reasons.append("Uses high-risk Android permissions")

        if "READ_SMS" in dangerous_perms or "RECEIVE_SMS" in dangerous_perms:
            attack_vectors.add("SMS interception")
            mitre.add("T1056 - Input Capture")

        if "SYSTEM_ALERT_WINDOW" in dangerous_perms:
            attack_vectors.add("Overlay phishing")

        if "BIND_ACCESSIBILITY_SERVICE" in dangerous_perms:
            attack_vectors.add("Device takeover via accessibility abuse")

    # =========================
    # EXE SIGNALS
    # =========================

    suspicious_funcs = apk_data.get("suspicious_functions", [])

    if suspicious_funcs:
        score += len(suspicious_funcs) * 10
        reasons.append("Suspicious Windows API usage detected")

        attack_vectors.add("Process injection / persistence")

        mitre.add("T1055 - Process Injection")

    # =========================
    # YARA SIGNALS
    # =========================

    yara = apk_data.get("yara_matches", [])

    if yara:
        score += len(yara) * 18
        reasons.append("Known malware signatures detected")

    # =========================
    # URL SIGNALS
    # =========================

    urls = apk_data.get("urls", [])

    if urls:
        score += len(urls) * 8
        reasons.append("External communication detected")

        attack_vectors.add("Command & Control (C2) communication")

    # =========================
    # SANDBOX SIGNALS
    # =========================

    if sandbox_data and sandbox_data.get("sandbox_run"):
        score += 15
        reasons.append("Behavior triggered sandbox execution")

    # =========================
    # FINAL NORMALIZATION
    # =========================

    score = min(score, 100)

    if score < 30:
        level = "LOW"
    elif score < 60:
        level = "MEDIUM"
    elif score < 85:
        level = "HIGH"
    else:
        level = "CRITICAL"

    # =========================
    # THREAT CLASSIFICATION
    # =========================

    if "READ_SMS" in dangerous_perms and "SYSTEM_ALERT_WINDOW" in dangerous_perms:
        threat_class = "Android Banking Trojan"

    elif "BIND_ACCESSIBILITY_SERVICE" in dangerous_perms:
        threat_class = "Accessibility-Based Spyware"

    elif suspicious_funcs:
        threat_class = "Windows Malware / Trojan"

    elif yara:
        threat_class = "Known Malware Family"

    else:
        threat_class = "Suspicious Application"

    # =========================
    # OUTPUT
    # =========================

    return {
        "risk_score": score,
        "risk_level": level,
        "threat_class": threat_class,
        "ai_summary": " ".join(reasons),
        "attack_vectors": list(attack_vectors),
        "mitre_mapping": list(mitre)
    }
