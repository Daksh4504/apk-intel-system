def calculate_risk(dangerous_permissions):
    score = 0
    reasons = []

    for perm in dangerous_permissions:
        if "SMS" in perm:
            score += 30
            reasons.append("SMS access detected")
        elif "BOOT" in perm:
            score += 15
            reasons.append("Auto-start on boot")
        elif "SYSTEM_ALERT_WINDOW" in perm:
            score += 25
            reasons.append("Overlay permission detected")
        else:
            score += 20
            reasons.append(f"High-risk permission: {perm}")

    if score <= 20:
        verdict = "SAFE"
    elif score <= 50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons
    }
