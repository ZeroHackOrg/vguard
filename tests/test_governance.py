from vguard.governance import PIIPolicy, SecretScanPolicy


def test_email_detected():
    findings = PIIPolicy().scan_text("contact alice@example.com now")
    assert any(f.category == "email" for f in findings)
    assert findings[0].value == "alice@example.com"


def test_ssn_and_phone_detected():
    policy = PIIPolicy()
    assert policy.has_match("SSN 123-45-6789")
    assert policy.has_match("call +1 415 555 0101")


def test_redaction():
    redacted = PIIPolicy().redact("email a@b.com and secret apikey=zkdfjaksjdfksjdfs123")
    assert "a@b.com" not in redacted
    assert "[REDACTED]" in redacted


def test_aws_key_detected():
    assert PIIPolicy().has_match("AKIAIOSFODNN7EXAMPLE")


def test_generic_secret_detected():
    assert PIIPolicy().has_match("api_key=supersecrettokenvalue123")


def test_high_entropy_scan():
    policy = SecretScanPolicy(min_entropy=3.0, min_length=8)
    findings = policy.scan_payload({"metadata": "g7Hx1mQz9pVb4wXr"})
    assert any(f.category == "high_entropy_secret" for f in findings)


def test_low_entropy_not_scanned():
    policy = SecretScanPolicy(min_entropy=3.0, min_length=8)
    assert policy.scan_payload({"metadata": "aaaaaaaa"}) == []