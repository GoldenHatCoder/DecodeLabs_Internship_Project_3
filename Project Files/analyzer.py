import base64
import html
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.I)
IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

PATTERNS = {
    "urgency": (re.compile(r"\b(urgent|immediately|act now|right away|expires?|final warning|within \d+\s*(?:hour|hours|minute|minutes))\b", re.I), 12, "Urgency or pressure language"),
    "credentials": (re.compile(r"\b(password|passcode|login|log in|sign in|credentials?|username|security code|verification code|otp|one[- ]time password)\b", re.I), 18, "Credential or authentication request"),
    "financial": (re.compile(r"\b(payment|pay now|invoice|refund|bank|credit card|debit card|gift card|crypto(?:currency)?|transfer money)\b", re.I), 16, "Financial or payment-related request"),
    "threat": (re.compile(r"\b(suspend(?:ed|ion)?|terminate(?:d|ion)?|locked|penalty|legal action|fine|lose access|account will be closed)\b", re.I), 15, "Threat or consequence language"),
    "reward": (re.compile(r"\b(congratulations|winner|won|prize|reward|bonus|free money|claim your)\b", re.I), 10, "Reward or prize bait"),
    "attachment": (re.compile(r"\b(attachment|attached file|document attached|download the file|open the document)\b", re.I), 8, "Attachment or download lure"),
    "secrecy": (re.compile(r"\b(do not tell|keep this secret|confidential|don't tell anyone|do not share)\b", re.I), 8, "Secrecy instruction"),
    "action": (re.compile(r"\b(click|tap|follow|verify|confirm|update|review|open|download|reply)\b", re.I), 7, "Call to action"),
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "click", "country", "work", "party", "gq", "tk"}

def _clean_url(raw):
    url = raw.rstrip(".,;:!?)]}")
    return url if url.lower().startswith(("http://", "https://")) else "http://" + url

def inspect_url(raw):
    url = _clean_url(raw)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings = []
    if parsed.scheme != "https":
        findings.append(("medium", "HTTP link", "The link does not use HTTPS."))
    if host in SHORTENERS or host.startswith("www.") and host[4:] in SHORTENERS:
        findings.append(("high", "URL shortener", "Shortened URLs can hide the final destination."))
    if "@" in parsed.netloc:
        findings.append(("high", "Embedded user information", "The URL contains @-style user information that can be deceptive."))
    if IP_HOST_RE.fullmatch(host or ""):
        findings.append(("high", "IP-address host", "The URL points directly to an IP address instead of a normal domain."))
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(("high", "Punycode domain", "The hostname uses Punycode and deserves careful inspection."))
    labels = [x for x in host.split(".") if x]
    if len(labels) >= 4:
        findings.append(("medium", "Deep subdomain", "The hostname contains several subdomain levels."))
    if len(url) > 120:
        findings.append(("medium", "Long URL", "An unusually long URL can conceal complex paths or parameters."))
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(("medium", "Unusual TLD", f".{tld} is flagged for additional review."))
    return {"url": url, "host": host, "scheme": parsed.scheme, "findings": [
        {"severity": s, "title": t, "explanation": e} for s, t, e in findings
    ]}

def analyze_message(message):
    findings = []
    score = 0
    for _, (pattern, points, title) in PATTERNS.items():
        if pattern.search(message):
            score += points
            findings.append({"severity": "high" if points >= 15 else "medium", "title": title,
                             "explanation": "Potential indicator detected in the submitted message.",
                             "points": points})
    urls = [inspect_url(x) for x in URL_RE.findall(message)]
    for item in urls:
        for f in item["findings"]:
            points = 14 if f["severity"] == "high" else 7
            score += points
            findings.append({"severity": f["severity"], "title": f["title"],
                             "explanation": f["explanation"], "points": points})
    score = min(score, 100)
    risk = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    recommendations = [
        "Do not click links or open unexpected attachments.",
        "Verify the sender through an independently known contact method.",
        "Never provide passwords, OTPs or payment details because a message asks for them.",
    ]
    if urls:
        recommendations.append("Inspect the destination domain carefully before taking any action.")
    return {
        "score": score, "risk": risk, "findings": findings, "urls": urls,
        "recommendations": recommendations,
        "red_flags": [f["title"] for f in findings],
        "summary": f"{risk} risk based on {len(findings)} detected indicator(s)."
    }

def decode_base64(value):
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return "Invalid Base64 input."

def rot13(value):
    return value.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

def decode_html_entities(value):
    return html.unescape(value)

if __name__ == "__main__":
    sample = "URGENT: verify your password at http://bit.ly/example immediately."
    print(analyze_message(sample))
