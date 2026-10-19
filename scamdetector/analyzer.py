"""Combines the ML model and the rule checks into one verdict with reasons."""

from dataclasses import dataclass, field
from functools import lru_cache

from .model import load_model, scam_probability
from .rules import Finding, check_text, check_url, extract_urls

ML_WEIGHT = 0.55
RULE_WEIGHT = 0.45
SCAM_THRESHOLD = 0.60
SUSPICIOUS_THRESHOLD = 0.35

ADVICE = {
    "Scam": [
        "Do NOT click any link, call any number or reply.",
        "Never share your OTP, UPI PIN, CVV or card number with anyone. Banks never ask for them.",
        "If you already shared details or paid: call your bank immediately and report at "
        "1930 (cyber fraud helpline) or cybercrime.gov.in.",
        "Block the sender and report the message to 1909 / the Sanchar Saathi portal (sancharsaathi.gov.in).",
    ],
    "Suspicious": [
        "Don't click the link yet. Open your bank's or company's official app or website yourself.",
        "Call the official customer care number printed on your card or on the official website.",
        "If unsure, ask a family member or forward it to a trusted person first.",
    ],
    "Looks safe": [
        "Nothing alarming found, but stay careful: never share your OTP or UPI PIN with anyone.",
        "When in doubt, open the official app directly instead of tapping links.",
    ],
}


@dataclass
class Result:
    verdict: str                 # "Scam", "Suspicious" or "Looks safe"
    score: float                 # 0 to 1 risk score
    ml_probability: float
    rule_score: float
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    warns_about_otp: bool = False
    advice: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def _model():
    return load_model()


def analyze(text: str) -> Result:
    text = (text or "").strip()
    if not text:
        raise ValueError("Please enter a message to analyze.")

    urls = extract_urls(text)
    text_findings, warns = check_text(text)
    url_findings = [f for u in urls for f in check_url(u)]
    findings = sorted(text_findings + url_findings, key=lambda f: f.weight, reverse=True)

    rule_score = min(1.0, sum(f.weight for f in findings))
    ml_prob = scam_probability(_model(), text)
    score = min(1.0, ML_WEIGHT * ml_prob + RULE_WEIGHT * rule_score)

    # A strong single red flag (e.g. asking for your PIN) should never be averaged away.
    if any(f.weight >= 0.45 for f in findings):
        score = max(score, SCAM_THRESHOLD)

    if score >= SCAM_THRESHOLD:
        verdict = "Scam"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "Suspicious"
    else:
        verdict = "Looks safe"

    return Result(verdict, round(score, 3), round(ml_prob, 3), round(rule_score, 3),
                  findings, urls, warns, ADVICE[verdict])
