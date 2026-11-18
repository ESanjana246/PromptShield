def calculate_risk_score(
    injection_result,
    leakage_result,
    ml_result=None
):
    score = 0
    reasons = []

    # 1. Prompt injection signal
    injection_level = str(
        injection_result.get("risk_level", "Low")
    ).lower()

    if injection_level == "high":
        score += 70
        reasons.append("High-risk prompt injection detected")

    elif injection_level == "medium":
        score += 35
        reasons.append("Possible prompt injection detected")

    # 2. Sensitive data leakage signal
    if leakage_result.get("data_leak_detected", False):
        detected_types = leakage_result.get(
            "detected_types", []
        )

        score += 40
        reasons.append(
            "Sensitive information detected: "
            + ", ".join(detected_types)
        )

    # 3. ML classification as supporting evidence
    if ml_result:
        prediction = str(
            ml_result.get("prediction", "")
        ).lower()

        try:
            confidence = float(
                ml_result.get("confidence", 0)
            )
        except (TypeError, ValueError):
            confidence = 0

        confidence = max(0, min(confidence, 100))

        if prediction == "suspicious":
            if confidence >= 80:
                score += 10
                reasons.append(
                    "ML strongly supports suspicious classification"
                )
            elif confidence >= 60:
                score += 5
                reasons.append(
                    "ML moderately supports suspicious classification"
                )

    # Keep score within 0-100
    score = min(score, 100)

    # 4. Final risk level
    if score >= 70:
        risk_level = "High"
    elif score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not reasons:
        reasons.append("No significant security risks detected")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risk_reasons": reasons
    }