import re
import ipaddress


# ---------------- PATTERN DEFINITIONS ----------------

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+91[\s-]?|91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\w)"
)

IP_PATTERN = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
)

CARD_PATTERN = re.compile(
    r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
)

API_PATTERNS = {
    "OpenAI-style API Key": re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    "Google API Key": re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    "GitHub Token": re.compile(
        r"\b(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{12,}\b"
    ),
    "Slack Token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "JWT Token": re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]{5,}\b"
    )
}

PASSWORD_PATTERN = re.compile(
    r"\b(?:password|passwd|pwd)\s*[:=]\s*"
    r"""(?:"[^"]+"|'[^']+'|[^\s,;]+)""",
    re.IGNORECASE
)

SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)"
    r"\s*[:=]\s*"
    r"""(?:"[^"]+"|'[^']+'|[^\s,;]+)""",
    re.IGNORECASE
)


# ---------------- VALIDATION FUNCTIONS ----------------

def mask_value(value):
    """Mask detected values to avoid exposing secrets."""

    if len(value) <= 4:
        return "*" * len(value)

    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def valid_phone(number):
    """Validate Indian mobile number format."""

    digits = re.sub(r"\D", "", number)

    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]

    elif digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]

    return len(digits) == 10 and digits[0] in "6789"


def valid_ip(address):
    """Check whether an IPv4 address is valid."""

    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def valid_card_number(number):
    """Validate card-like numbers using the Luhn checksum."""

    digits = re.sub(r"\D", "", number)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for index, digit in enumerate(reverse_digits):
        value = int(digit)

        if index % 2 == 1:
            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


# ---------------- MAIN DETECTION FUNCTION ----------------

def detect_sensitive_data(text):

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    detections = []

    def add_detection(category, value):
        detections.append({
            "category": category,
            "masked_value": mask_value(value)
        })

    # 1. Email detection
    for match in EMAIL_PATTERN.finditer(text):
        add_detection("Email Address", match.group())

    # 2. Indian mobile number detection
    for match in PHONE_PATTERN.finditer(text):
        value = match.group()

        if valid_phone(value):
            add_detection("Phone Number", value)

    # 3. IP address detection
    for match in IP_PATTERN.finditer(text):
        value = match.group()

        if valid_ip(value):
            add_detection("IP Address", value)

    # 4. Credit/debit card-like number detection
    for match in CARD_PATTERN.finditer(text):
        value = match.group()

        if valid_card_number(value):
            add_detection("Credit/Debit Card Number", value)

    # 5. API key and token detection
    for category, pattern in API_PATTERNS.items():
        for match in pattern.finditer(text):
            add_detection(category, match.group())

    # 6. Password detection
    for match in PASSWORD_PATTERN.finditer(text):
        value = match.group().split("=", 1)[-1].split(":", 1)[-1].strip()
        value = value.strip("\"'")

        if value:
            add_detection("Password", value)

    # 7. Other named secret assignments
    for match in SECRET_ASSIGNMENT_PATTERN.finditer(text):
        value = re.split(r"[:=]", match.group(), maxsplit=1)[-1].strip()
        value = value.strip("\"'")

        if value:
            add_detection("Secret / Access Token", value)

    # Remove duplicate detections
    unique_detections = []
    seen = set()

    for item in detections:
        key = (item["category"], item["masked_value"])

        if key not in seen:
            seen.add(key)
            unique_detections.append(item)

    detected_types = list(dict.fromkeys(
        item["category"] for item in unique_detections
    ))

    return {
        "data_leak_detected": bool(unique_detections),
        "detected_types": detected_types,
        "detections": unique_detections,
        "detection_count": len(unique_detections),
        "risk_level": "High" if unique_detections else "Low"
    }