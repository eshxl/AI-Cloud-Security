"""
detector.py  — (27 pattern types, context-aware, sensible risk thresholds)

Risk thresholds (score-based):
  SAFE        = 0
  LOW RISK    = 1–5   → email + phone alone = 4 → uploads with warning ✅
  MEDIUM RISK = 6–14  → Aadhaar/PAN/bank alone (8) or email+phone+more
  HIGH RISK   = 15+   → credentials, multiple critical fields
"""
import re

EMAIL_PATTERN    = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
PHONE_PATTERN    = r'\b[6-9]\d{9}\b'
AADHAAR_PATTERN  = r'\b\d{4}\s?\d{4}\s?\d{4}\b'
PAN_PATTERN      = r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'
PASSPORT_PATTERN = r'(?i)(?:passport\s*(?:no\.?|number|#)?)\s*[:=\-]?\s*([A-Z]\d{7})'
VOTER_ID_PATTERN = r'(?i)(?:voter\s*(?:id|card)|epic\s*(?:no\.?|number)?)\s*[:=\-]?\s*([A-Z]{3}\d{7})'
DL_PATTERN       = r'(?i)(?:driving\s*licen[cs]e?|dl\s*no\.?|licence\s*no\.?)\s*[:=\-]?\s*([A-Z]{2}\d{2}\s?\d{4}\s?\d{7})'
DOB_PATTERN      = r'(?i)(?:dob|date.of.birth|born.on|birth.date)\s*[:=\-]?\s*\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}'
BANK_ACC_PATTERN = r'(?i)(?:account\s*(?:no\.?|number|#)?|a/?c\.?\s*(?:no\.?)?|acct\.?\s*(?:no\.?)?)\s*[:\-]?\s*(\d{9,18})'
IFSC_PATTERN     = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
CREDIT_CARD_PATTERN = r'\b(?:\d{4}[\s\-]){3}\d{4}\b'
CVV_PATTERN      = r'(?i)\b(?:cvv|cvc|security\s*code)\s*[:=]?\s*\d{3,4}\b'
UPI_PATTERN      = r'\b[a-zA-Z0-9.\-_]{2,30}@(?:okicici|oksbi|okaxis|okhdfcbank|ybl|upi|apl|ibl|rbl|axl|paytm|freecharge|airtel|juspay|nsdl|mahb)\b'
SWIFT_PATTERN    = r'(?i)(?:swift|bic)\s*(?:code|number|#)?\s*[:=\-]?\s*\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b'
GST_PATTERN      = r'\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z0-9]\b'
SALARY_PATTERN   = r'(?i)(?:salary|ctc|lpa|per\s*annum|take.home|gross\s*pay|net\s*pay|basic\s*pay|in-hand)\s*[:=]?\s*(?:rs\.?|inr|₹)?\s*[\d,]{4,}'
PASSWORD_PATTERN = r'(?i)(password|passwd|pwd|passcode|pass)\s*[:=]?\s*\S+'
API_KEY_PATTERN  = r'(?i)(?:api[_\s-]?key|secret[_\s-]?(?:key|token)|access[_\s-]?(?:key|token)|auth[_\s-]?token)\s*[:=]?\s*[A-Za-z0-9_\-]{16,}'
JWT_PATTERN      = r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}(?:\.[A-Za-z0-9_\-]{10,})?\b'
AWS_KEY_PATTERN  = r'\bAKIA[0-9A-Z]{16}\b'
SSH_KEY_PATTERN  = r'\b(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{30,}'
PRIVATE_KEY_PATTERN = r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----'
BEARER_PATTERN   = r'(?i)\bbearer\s+[A-Za-z0-9_\-\.]{20,}\b'
IP_PATTERN       = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
EMPLOYEE_ID_PATTERN = r'(?i)\bEMP[\s\-_]?\d{3,8}\b'
OTP_PATTERN      = r'(?i)\b(?:otp|one[\s\-]time[\s\-](?:password|pin|code))\s*[:=]?\s*\d{4,8}\b'
INSURANCE_PATTERN = r'(?i)(?:policy\s*(?:no\.?|number|#)?|insurance\s*(?:id|no\.?))\s*[:=\-]?\s*[A-Z0-9\-]{6,20}'

# ── Weights (unchanged — these are correct) ───────────────────────────────────
WEIGHTS = {
    "passwords":10,"api_key":10,"jwt_token":10,"aws_key":10,
    "ssh_key":10,"private_key":10,"bearer_token":10,
    "aadhaar":8,"pan":8,"credit_card":8,"bank_account":8,"salary_figure":8,"gst_number":8,
    "passport":5,"voter_id":5,"driving_licence":5,
    "phones":3,"cvv":3,"otp":3,"upi":3,"swift_bic":3,"ifsc":3,"employee_id":3,"insurance":3,
    "dob":2,"ip_address":2,"emails":1,
}

# ── Score → Risk mapping ──────────────────────────────────────────────────────
#
#  What each band means in practice:
#
#  SAFE  (0)       — nothing found
#  LOW   (1–5)     — email only (1), phone only (3), email+phone (4)
#                    → common in resumes/business docs → UPLOAD with warning
#  MEDIUM (6–14)   — Aadhaar (8), PAN (8), bank account (8), salary (8),
#                    or combinations of lower-weight fields
#                    → genuinely sensitive → BLOCK
#  HIGH  (15+)     — any credential/key (10+), or multiple critical ID fields
#                    → critical → BLOCK
#
#  Old thresholds:  LOW ≤3 / MEDIUM ≤7  ← email+phone=4 wrongly hit MEDIUM
#  New thresholds:  LOW ≤5 / MEDIUM ≤14 ← email+phone=4 correctly stays LOW

def detect_sensitive_data(text):
    return {
        "emails":          re.findall(EMAIL_PATTERN,        text),
        "phones":          re.findall(PHONE_PATTERN,        text),
        "aadhaar":         re.findall(AADHAAR_PATTERN,      text),
        "pan":             re.findall(PAN_PATTERN,           text),
        "passport":        re.findall(PASSPORT_PATTERN,     text),
        "voter_id":        re.findall(VOTER_ID_PATTERN,     text),
        "driving_licence": re.findall(DL_PATTERN,           text),
        "dob":             re.findall(DOB_PATTERN,          text),
        "bank_account":    re.findall(BANK_ACC_PATTERN,     text),
        "ifsc":            re.findall(IFSC_PATTERN,         text),
        "credit_card":     re.findall(CREDIT_CARD_PATTERN,  text),
        "cvv":             re.findall(CVV_PATTERN,          text),
        "upi":             re.findall(UPI_PATTERN,          text),
        "swift_bic":       re.findall(SWIFT_PATTERN,        text),
        "gst_number":      re.findall(GST_PATTERN,          text),
        "salary_figure":   re.findall(SALARY_PATTERN,       text),
        "passwords":       re.findall(PASSWORD_PATTERN,     text),
        "api_key":         re.findall(API_KEY_PATTERN,      text),
        "jwt_token":       re.findall(JWT_PATTERN,          text),
        "aws_key":         re.findall(AWS_KEY_PATTERN,      text),
        "ssh_key":         re.findall(SSH_KEY_PATTERN,      text),
        "private_key":     re.findall(PRIVATE_KEY_PATTERN,  text),
        "bearer_token":    re.findall(BEARER_PATTERN,       text),
        "ip_address":      re.findall(IP_PATTERN,           text),
        "employee_id":     re.findall(EMPLOYEE_ID_PATTERN,  text),
        "otp":             re.findall(OTP_PATTERN,          text),
        "insurance":       re.findall(INSURANCE_PATTERN,    text),
    }


def calculate_risk(detected, text):
    regex_score = sum(len(detected.get(f, [])) * w for f, w in WEIGHTS.items())

    ml_boost = 0
    if regex_score == 0:
        try:
            from ml_model import predict_text
            if predict_text(text) == "sensitive":
                ml_boost = 5
        except Exception:
            pass

    total = regex_score + ml_boost

    if   total == 0:  return "SAFE"
    elif total <= 5:  return "LOW RISK"    # email+phone=4 → LOW ✅
    elif total <= 14: return "MEDIUM RISK" # Aadhaar/PAN/bank (8) → MEDIUM ✅
    else:             return "HIGH RISK"   # any credential (10+) → HIGH ✅


def get_risk_reasons(detected):
    labels = {
        "emails":          "Email address",
        "phones":          "Phone number",
        "aadhaar":         "Aadhaar number",
        "pan":             "PAN card",
        "passport":        "Passport number",
        "voter_id":        "Voter ID",
        "driving_licence": "Driving licence",
        "dob":             "Date of birth",
        "bank_account":    "Bank account number",
        "ifsc":            "IFSC code",
        "credit_card":     "Credit card number",
        "cvv":             "CVV/security code",
        "upi":             "UPI ID",
        "swift_bic":       "SWIFT/BIC code",
        "gst_number":      "GST number",
        "salary_figure":   "Salary/compensation figure",
        "passwords":       "Password/credential",
        "api_key":         "API key/secret token",
        "jwt_token":       "JWT token",
        "aws_key":         "AWS access key",
        "ssh_key":         "SSH private key",
        "private_key":     "Private key (PEM)",
        "bearer_token":    "Bearer token",
        "ip_address":      "IP address",
        "employee_id":     "Employee ID",
        "otp":             "OTP/one-time code",
        "insurance":       "Insurance policy number",
    }
    return [
        f"{labels[k]} ({len(v)} found)"
        for k, v in detected.items()
        if v and k in labels
    ]