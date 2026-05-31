# ==========================
# MALGUARD AI THREAT ENGINE
# ==========================

def classify_threat(static, url_data=None, sandbox_data=None):

    # ==========================
    # INITIAL STATE
    # ==========================

    score = 0
    reasons = []
    attack_vectors = set()
    mitre = set()

    analysis = static.get("analysis", {})

    yara_matches = analysis.get("yara_matches", [])
    dangerous_permissions = analysis.get("dangerous_permissions", [])
    suspicious_functions = analysis.get("suspicious_functions", [])
    urls = analysis.get("urls", [])

    # ==========================
    # STATIC ANALYSIS SCORING
    # ==========================

    if yara_matches:
        score += len(yara_matches) * 35
        reasons.append("YARA rule matches detected")
        attack_vectors.add("Known malware signature")

    if dangerous_permissions:
        score += len(dangerous_permissions) * 10
        reasons.append("Dangerous permissions detected (Android abuse risk)")
        attack_vectors.add("Privilege abuse")

    if suspicious_functions:
        score += len(suspicious_functions) * 15
        reasons.append("Suspicious API usage detected")
        attack_vectors.add("Process injection / system manipulation")

    # ==========================
    # SANDBOX BEHAVIOR SCORING
    # ==========================

    if sandbox_data:

        if sandbox_data.get("process_activity"):
            score += 20
            reasons.append("Suspicious process activity observed")
            attack_vectors.add("Process execution anomalies")

        if sandbox_data.get("network_activity"):
            score += 30
            reasons.append("Unusual network activity detected")
            attack_vectors.add("Command & Control communication")

        score += sandbox_data.get("behavior_score", 0) * 0.4

    # ==========================
    # URL INTELLIGENCE SCORING (YOUR ADDED BLOCK)
    # ==========================

    if url_data:
        avg = url_data.get("average_risk", 0)

        score += avg * 0.3

        if avg > 70:
            reasons.append(
                "High-risk URLs detected (possible C2 or phishing infrastructure)"
            )
            attack_vectors.add("Phishing / Command & Control communication")
            mitre.add("T1566 - Phishing")

    # ==========================
    # FINAL NORMALIZATION
    # ==========================

    score = min(int(score), 100)

    if score < 30:
        risk_level = "LOW"
    elif score < 60:
        risk_level = "MEDIUM"
    elif score < 85:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # ==========================
    # ATTACK CLASSIFICATION
    # ==========================

    if score >= 85:
        threat_class = "Severe Malware / Banking Trojan"
    elif score >= 60:
        threat_class = "Suspicious / Potential Malware"
    elif score >= 30:
        threat_class = "Low Risk / Heuristic Match"
    else:
        threat_class = "Clean / Safe"

    # ==========================
    # FINAL OUTPUT
    # ==========================

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "threat_class": threat_class,
        "reasons": reasons,
        "attack_vectors": list(attack_vectors),
        "mitre_attack": list(mitre)
    }
