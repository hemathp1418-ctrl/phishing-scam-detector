import pytest

from scamdetector.analyzer import analyze
from scamdetector.rules import check_text, check_url, extract_urls


def test_extracts_urls():
    urls = extract_urls("Update KYC at http://sbi-kyc.xyz/login or visit www.example.com.")
    assert "http://sbi-kyc.xyz/login" in urls
    assert "www.example.com" in urls


def test_lookalike_domain_is_flagged():
    reasons = " ".join(f.reason for f in check_url("http://sbi-update.xyz"))
    assert "NOT an official" in reasons


def test_real_bank_domain_is_not_lookalike():
    reasons = " ".join(f.reason for f in check_url("https://www.onlinesbi.sbi"))
    assert "NOT an official" not in reasons


def test_shortener_is_flagged():
    assert any("shortened" in f.reason for f in check_url("https://bit.ly/abc123"))


def test_otp_request_is_flagged_but_warning_is_not():
    bad, _ = check_text("Please share your OTP to avoid deactivation.")
    good, warns = check_text("Your OTP is 123456. Do not share it with anyone.")
    assert any("OTP" in f.reason for f in bad)
    assert not any("OTP" in f.reason for f in good)
    assert warns


@pytest.mark.parametrize("msg", [
    "Dear SBI user your account is locked, verify now at http://sbi-yono-verify.top/login",
    "Rs 9999 reward is waiting. Open bit.ly/3xK9pQ and enter UPI PIN to receive.",
    "Install AnyDesk and tell me the code so I can refund your money",
])
def test_known_scams_are_not_safe(msg):
    assert analyze(msg).verdict in ("Scam", "Suspicious")


@pytest.mark.parametrize("msg", [
    "Rs 450.00 debited from A/c XX1234 on 17-Oct-26 to ZOMATO via UPI. Ref 629384756.",
    "Hi, what time is the lab tomorrow?",
    "Your OTP is 482913 for HDFC NetBanking. Do not share this with anyone.",
])
def test_normal_messages_are_safe(msg):
    assert analyze(msg).verdict == "Looks safe"


def test_empty_message_raises():
    with pytest.raises(ValueError):
        analyze("   ")
