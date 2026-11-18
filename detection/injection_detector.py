import re


# Prompt injection detection patterns
INJECTION_PATTERNS = {

    "Instruction Override": [
        r"\bignore\b.{0,50}\b(previous|prior|all|above)\b.{0,30}\binstructions?\b",
        r"\bdisregard\b.{0,50}\binstructions?\b",
        r"\bforget\b.{0,50}\binstructions?\b",
        r"\boverride\b.{0,50}\binstructions?\b",
        r"\bfollow my commands instead\b",
        r"\bnew instructions take priority\b",
        r"\bignore\b.{0,30}\byour rules\b",
        r"\bignore\b.{0,30}\brules\b"
    ],

    "System Prompt Extraction": [
        r"\b(reveal|show|print|display|repeat|expose)\b.{0,60}\b(system|hidden|secret)\b.{0,30}\b(prompt|instructions?)\b",
        r"\bwhat are your hidden instructions\b",
        r"\bdescribe the instructions that control your responses\b",
        r"\bshow me the instructions that control your responses\b",
        r"\breveal\b.{0,40}\bconfidential instructions\b",
        r"\bprivate instructions\b"
    ],

    "Safety Bypass": [
        r"\bbypass\b.{0,40}\b(safety|security|rules|restrictions)\b",
        r"\bignore\b.{0,40}\b(safety|security) guidelines\b",
        r"\bdisable\b.{0,30}\b(restrictions|safeguards)\b",
        r"\bact without restrictions\b",
        r"\bremove\b.{0,30}\bsafety restrictions\b"
    ],

    "Role Manipulation": [
        r"\byou are now\b.{0,40}\b(unrestricted|unfiltered)\b",
        r"\bpretend\b.{0,40}\b(no rules|unrestricted)\b",
        r"\bact as\b.{0,40}\b(unrestricted assistant|unfiltered ai)\b",
        r"\bchange your role\b",
        r"\bact as a different assistant\b"
    ]
}


def detect_prompt_injection(prompt):

    if not isinstance(prompt, str) or not prompt.strip():
        return {
            "is_suspicious": False,
            "detected_categories": [],
            "risk_level": "Low"
        }

    detected_patterns = []

    # Check all categories
    for category, patterns in INJECTION_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, prompt, re.IGNORECASE | re.DOTALL):
                detected_patterns.append(category)
                break

    # Calculate detection risk
    if len(detected_patterns) >= 2:
        risk_level = "High"

    elif len(detected_patterns) == 1:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    return {
        "is_suspicious": len(detected_patterns) > 0,
        "detected_categories": detected_patterns,
        "risk_level": risk_level
    }