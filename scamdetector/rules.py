"""Rule-based scam checks.

These rules look for well-known scam tricks (fake urgency, requests for OTP/PIN,
look-alike domains, ...). Every rule has a weight and a plain-English reason,
so the app can explain WHY a message looks risky.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Finding:
    reason: str
    weight: float  # how strongly this points to a scam (0 to 1)
    kind: str      # "text" or "url"


# ---------------------------------------------------------------- URL helpers

URL_RE = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+|"
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\."
    r"(?:com|in|xyz|top|click|link|info|net|org|ly|me|site|online|vip|live|cc|tk|gq|ml|cf|icu|shop|buzz)"
    r"\b(?:/[^\s]*)?)",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "tk", "gq", "ml", "cf", "vip", "cc", "link", "buzz"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "ow.ly",
}

# brand keyword -> that brand's real domains
OFFICIAL_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net", "hdfc.com"],
    "icici": ["icicibank.com", "icici.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "npci": ["npci.org.in"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "uidai": ["uidai.gov.in"],
    "indiapost": ["indiapost.gov.in"],
    "bescom": ["bescom.co.in", "bescom.org"],
}


def extract_urls(text: str) -> list[str]:
    urls = [u.rstrip(".,;:!?)\"'") for u in URL_RE.findall(text)]
    # remove duplicates, keep order
    return list(dict.fromkeys(urls))


def _hostname(url: str) -> str:
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def check_url(url: str) -> list[Finding]:
    findings: list[Finding] = []
    host = _hostname(url)
    if not host:
        return findings

    if host in SHORTENERS:
        findings.append(Finding(
            f"{url} is a shortened link, so you can't see where it really leads.", 0.20, "url"))

    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding(
            f"{host} ends in .{tld}, an extension often used for throwaway scam sites.", 0.25, "url"))

    # look-alike of a real brand, e.g. sbi-update.xyz
    compact = host.replace("-", "").replace(".", "")
    for brand, real_domains in OFFICIAL_DOMAINS.items():
        if brand in compact:
            is_real = any(host == d or host.endswith("." + d) for d in real_domains)
            if not is_real:
                findings.append(Finding(
                    f"{host} uses the name '{brand.upper()}' but is NOT an official "
                    f"{brand.upper()} website ({real_domains[0]} is).", 0.50, "url"))
                break

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        findings.append(Finding("The link uses a raw IP address instead of a website name.", 0.40, "url"))

    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        findings.append(Finding("The link contains '@', a trick used to hide the real address.", 0.30, "url"))

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(Finding("The link uses look-alike (punycode) characters.", 0.30, "url"))

    if host.count("-") >= 2:
        findings.append(Finding(f"{host} has many hyphens, common in fake domains.", 0.15, "url"))

    if url.lower().startswith("http://"):
        findings.append(Finding("The link is not secure (http, not https).", 0.10, "url"))

    return findings


# ---------------------------------------------------------------- text rules

# (regex, weight, reason)
TEXT_RULES = [
    (r"\b(urgent|immediately|within \d+ ?(hours?|hrs?|mins?|minutes?)|today only|last (warning|chance)|"
     r"expires? (today|soon)|act now|final notice|tonight|before it expires)\b",
     0.15, "Creates fake urgency to make you act without thinking."),

    (r"\b(block(ed)?|suspend(ed)?|deactivat(ed|ion)|disconnect(ed|ion)?|frozen|freeze|terminated|"
     r"legal action|arrest|penalty|cancelled|(will be|is) cut|power cut|jail)\b",
     0.15, "Threatens that something will be blocked, closed or punished."),

    (r"\b(kyc|re-?kyc|pan (card )?(update|verification|details)|aadhaar (update|verification|is linked))\b",
     0.20, "Mentions KYC/PAN/Aadhaar updates, a very common scam excuse."),

    (r"\b(share|send|tell|provide|enter|give|reply with|submit|verify)\b[^.]{0,40}"
     r"\b(otp|pin|cvv|password|upi pin|card number|bank details)\b",
     0.45, "Asks for your OTP, PIN, CVV, password or card/bank details. Real banks never do this."),

    (r"(collect request|request money|approve (the |this )?(request|collect)|"
     r"enter (your )?(upi )?pin to (receive|get|claim)|approving the request)",
     0.40, "Asks you to approve a UPI request or enter your PIN to 'receive' money. "
           "A PIN is only ever needed to SEND money."),

    (r"\b(you have won|you've won|won rs|winner|lottery|lucky draw|prize|congratulations|"
     r"free recharge|brand new (iphone|phone)|selected for)\b",
     0.25, "Claims you won something or were 'selected'. If you didn't enter, it's a trap."),

    (r"(processing fee|customs (fee|duty|charges?)|release (your )?(parcel|package|amount|loan)|"
     r"registration fee|redelivery fee|clearance (fee|charges?)|delivery charges to get|pay a small)",
     0.30, "Asks for a 'small fee' to release a parcel, prize or loan."),

    (r"\b(anydesk|teamviewer|quicksupport|airdroid|rustdesk)\b",
     0.45, "Asks you to install a remote-access app, which lets scammers control your phone."),

    (r"(work from home|part[- ]time job|earn (rs\.?|₹)?\s?[\d,]+\s?(per|/|a)\s?(day|hour|daily)|"
     r"like (and )?subscribe|task[- ]based|daily income)",
     0.30, "Offers easy money for simple work. A classic job scam."),

    (r"\b(cbi|narcotics|customs officer|cyber ?crime|police|trai|rbi)\b[^.]{0,80}"
     r"\b(case|arrest|warrant|parcel|drugs|money laundering|illegal)\b",
     0.35, "Pretends to be police/CBI/customs ('digital arrest'). Real agencies don't arrest over calls or SMS."),

    (r"(instant loan|pre-?approved loan|loan (is )?approved|no documents needed)",
     0.25, "Offers an instant loan with no checks, typical of predatory loan apps."),

    (r"(sent (you )?rs\.?\s?[\d,]+ (by )?mistake|by error|wrongly (sent|transferred)|return (it|the money))",
     0.30, "Says money was sent to you 'by mistake' and asks for it back."),

    (r"\bdear (customer|user|account holder|sir/?madam|valued|cardholder)\b",
     0.10, "Uses a generic greeting instead of your name."),

    (r"(refund|subsidy|cashback)[^.]{0,60}(approved|pending|credited|eligible)[^.]{0,60}"
     r"(click|link|submit|verify|details|http|www)",
     0.30, "Promises a refund/subsidy/cashback if you click a link or submit details."),


    (r"\b(transfer|send|pay|deposit)\b[^.]{0,25}\b(rs\.?|₹)?\s?\d[\d,]{2,}\b[^.]{0,40}\b(now|immediately|today|urgent|or he|or she|or your)\b",
     0.30, "Demands money to be sent right now."),

    (r"(\b(join|contact|message|dm)\b[^.]{0,25}\btelegram\b|\btelegram\b[^.]{0,25}\b(join|task|earn)\b|simple tasks?)",
     0.20, "Pushes you to Telegram/WhatsApp for 'tasks' or easy earnings."),

    (r"(do not disconnect|don't disconnect|do not tell|don't tell anyone|keep this confidential)",
     0.35, "Tells you to stay on the call or keep it secret. Scammers isolate their victims."),
]

COMPILED_TEXT_RULES = [(re.compile(p, re.IGNORECASE), w, r) for p, w, r in TEXT_RULES]

# phrases real banks use to WARN you; remove them before looking for "share otp"
SAFE_WARNINGS = re.compile(
    r"(do not|don't|never|dont)\s+(share|disclose|give|tell)\b[^.]*",
    re.IGNORECASE,
)
NEVER_ASK = re.compile(r"never asks? (for )?[^.]{0,40}(otp|pin|cvv)[^.]*", re.IGNORECASE)


def check_text(text: str) -> tuple[list[Finding], bool]:
    """Returns (findings, message_warns_you_about_sharing_otp)."""
    warns = bool(SAFE_WARNINGS.search(text) or NEVER_ASK.search(text))
    cleaned = NEVER_ASK.sub(" ", SAFE_WARNINGS.sub(" ", text))
    findings = [Finding(reason, weight, "text")
                for pattern, weight, reason in COMPILED_TEXT_RULES
                if pattern.search(cleaned)]
    return findings, warns
