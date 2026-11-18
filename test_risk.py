from detection.risk_scorer import calculate_risk_score

tests = [
    {
        "name": "Normal prompt",
        "injection": {"risk_level": "Low"},
        "leakage": {"data_leak_detected": False},
        "ml": {"prediction": "normal", "confidence": 95}
    },
    {
        "name": "Possible injection",
        "injection": {"risk_level": "Medium"},
        "leakage": {"data_leak_detected": False},
        "ml": {"prediction": "normal", "confidence": 80}
    },
    {
        "name": "Sensitive data",
        "injection": {"risk_level": "Low"},
        "leakage": {
            "data_leak_detected": True,
            "detected_types": ["Email Address"]
        },
        "ml": {"prediction": "normal", "confidence": 90}
    },
    {
        "name": "Combined risks",
        "injection": {"risk_level": "High"},
        "leakage": {
            "data_leak_detected": True,
            "detected_types": ["Email Address"]
        },
        "ml": {"prediction": "suspicious", "confidence": 90}
    }
]

for test in tests:
    result = calculate_risk_score(
        test["injection"],
        test["leakage"],
        test["ml"]
    )

    print("\nTest:", test["name"])
    print("Score:", result["risk_score"])
    print("Risk:", result["risk_level"])
    print("Reasons:", result["risk_reasons"])