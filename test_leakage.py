from detection.leakage_detector import detect_sensitive_data

tests = [
    ("Normal prompt", "Explain artificial intelligence."),
    ("Email", "Contact me at test@example.com"),
    ("Phone", "My number is 9876543210"),
    ("Invalid phone", "My number is 1234567890"),
    ("IP address", "Server address is 192.168.1.10"),
    ("Invalid IP", "Server address is 999.999.999.999"),
    ("Password", "password=example123"),
    ("API key", "API key: sk-abcdefghijklmnop"),
    ("Ordinary digits", "My roll number is 123456"),
]

for name, prompt in tests:
    result = detect_sensitive_data(prompt)

    print("\nTest:", name)
    print("Detected:", result["data_leak_detected"])
    print("Types:", result["detected_types"])
    print("Risk:", result["risk_level"])