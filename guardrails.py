"""
guardrails.py
-------------
All guardrail logic for SafeChat Gateway.
Provides 6 regex/rule-based guardrails (4 input checks, 2 output checks)
and runner functions that execute them in sequence.
"""

import re
from typing import Dict, Any, List, Optional

# ============================================================================
# CONFIGURABLE CONSTANTS
# ============================================================================

# Maximum allowed words for a user input prompt
MAX_WORD_COUNT = 100

# Phrases commonly used in prompt injection / jailbreak attempts (case-insensitive)
PROMPT_INJECTION_PHRASES = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "disregard your instructions",
    "disregard all instructions",
    "forget your rules",
    "forget all rules",
    "reveal your system prompt",
    "you are now dan",
    "act as an unrestricted ai",
]

# Regex patterns matching prompt injection variations
PROMPT_INJECTION_PATTERNS = [
    r"\bignore\s+(all\s+)?previous\s+instructions\b",
    r"\bdisregard\s+(all\s+)?(your\s+)?instructions\b",
    r"\bforget\s+(all\s+)?(your\s+)?rules\b",
    r"\breveal\s+(your\s+)?system\s+prompt\b",
    r"\byou\s+are\s+now\s+dan\b",
    r"\bact\s+as\s+an\s+unrestricted\s+ai\b",
]

# Sensitive PII patterns
SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"
# Credit card: 13-16 digits with optional spaces or dashes
CREDIT_CARD_PATTERN = r"\b(?:\d{4}[ -]?){3}\d{1,4}\b|\b\d{13,16}\b"
# Phone number: standard US/international formats e.g. 555-123-4567, (555) 123-4567, +1-555-123-4567
PHONE_PATTERN = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"

# API Key patterns
API_KEY_PATTERNS = {
    "OpenAI API Key (sk-...)": r"\bsk-[A-Za-z0-9_\-]{20,}\b",
    "Google Gemini API Key (AIza...)": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "AWS Access Key ID (AKIA...)": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub Token (ghp_...)": r"\bghp_[0-9A-Za-z]{36,}\b",
}

# Email pattern for output redaction
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

# Suspicious Top-Level Domains (TLDs) for output URL validation
SUSPICIOUS_TLDS = [".zip", ".xyz", ".tk", ".ru", ".click"]

# IP-based URL pattern (e.g. http://192.168.1.1/login or https://10.0.0.1)
IP_URL_PATTERN = r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?"


# ============================================================================
# INPUT GUARDRAILS (Door Checks)
# ============================================================================

def check_word_count(text: str, max_words: int = MAX_WORD_COUNT) -> Dict[str, Any]:
    """
    Input Guardrail 1: Word Count Limit
    Blocks messages that exceed the maximum word count threshold.
    """
    words = text.strip().split()
    count = len(words)

    if count > max_words:
        return {
            "name": "Word Count Limit",
            "status": "blocked",
            "message": f"Message contains {count} words, which exceeds the limit of {max_words} words.",
            "text": text,
        }
    return {
        "name": "Word Count Limit",
        "status": "passed",
        "message": f"Word count ({count}) is within the safe limit of {max_words} words.",
        "text": text,
    }


def check_prompt_injection(text: str) -> Dict[str, Any]:
    """
    Input Guardrail 2: Prompt Injection Detector
    Blocks common adversarial attempts to bypass system instructions.
    """
    text_lower = text.lower()

    # Check explicit phrases first
    for phrase in PROMPT_INJECTION_PHRASES:
        if phrase in text_lower:
            return {
                "name": "Prompt Injection Detector",
                "status": "blocked",
                "message": f"Blocked attempt to manipulate system rules (matched phrase: '{phrase}').",
                "text": text,
            }

    # Check regex variations
    for pattern in PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return {
                "name": "Prompt Injection Detector",
                "status": "blocked",
                "message": f"Blocked potential prompt injection pattern ('{match.group(0)}').",
                "text": text,
            }

    return {
        "name": "Prompt Injection Detector",
        "status": "passed",
        "message": "No prompt injection or jailbreak patterns detected.",
        "text": text,
    }


def check_pii(text: str) -> Dict[str, Any]:
    """
    Input Guardrail 3: PII Detector
    Blocks messages containing SSNs, credit cards, or phone numbers.
    """
    detected_types = []

    if re.search(SSN_PATTERN, text):
        detected_types.append("Social Security Number (SSN)")

    # Check credit card
    cc_match = re.search(CREDIT_CARD_PATTERN, text)
    if cc_match:
        # Validate that the match has between 13 and 16 digits
        digits_only = re.sub(r"\D", "", cc_match.group(0))
        if 13 <= len(digits_only) <= 16:
            detected_types.append("Credit Card Number")

    # Check phone number
    if re.search(PHONE_PATTERN, text):
        detected_types.append("Phone Number")

    if detected_types:
        unique_types = list(dict.fromkeys(detected_types))
        return {
            "name": "PII Detector",
            "status": "blocked",
            "message": f"Blocked sensitive Personal Identifiable Information: {', '.join(unique_types)}.",
            "text": text,
        }

    return {
        "name": "PII Detector",
        "status": "passed",
        "message": "No sensitive PII (SSN, credit card, phone number) detected.",
        "text": text,
    }


def check_api_keys(text: str) -> Dict[str, Any]:
    """
    Input Guardrail 4: API Key Detector
    Blocks messages containing leaked API keys, tokens, or credentials.
    """
    for key_name, pattern in API_KEY_PATTERNS.items():
        if re.search(pattern, text):
            return {
                "name": "API Key Detector",
                "status": "blocked",
                "message": f"Blocked exposed secret credential: {key_name}.",
                "text": text,
            }

    return {
        "name": "API Key Detector",
        "status": "passed",
        "message": "No secret API keys or credentials detected.",
        "text": text,
    }


# ============================================================================
# OUTPUT GUARDRAILS (Exit Checks)
# ============================================================================

def redact_pii(text: str) -> Dict[str, Any]:
    """
    Output Guardrail 5: PII Redactor
    Replaces email addresses and credit card numbers in Gemini's reply with [REDACTED].
    Status is 'modified' if any replacement occurred, otherwise 'passed'.
    """
    redacted_text = text
    modifications = []

    # Redact email addresses
    if re.search(EMAIL_PATTERN, redacted_text):
        redacted_text = re.sub(EMAIL_PATTERN, "[REDACTED]", redacted_text)
        modifications.append("email address")

    # Redact credit card numbers
    def _mask_cc(match):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 16:
            return "[REDACTED]"
        return match.group(0)

    cc_replaced = re.sub(CREDIT_CARD_PATTERN, _mask_cc, redacted_text)
    if cc_replaced != redacted_text:
        redacted_text = cc_replaced
        modifications.append("credit card number")

    if modifications:
        return {
            "name": "PII Redactor",
            "status": "modified",
            "message": f"Redacted sensitive {', '.join(modifications)} for privacy protection.",
            "text": redacted_text,
        }

    return {
        "name": "PII Redactor",
        "status": "passed",
        "message": "No sensitive emails or credit card numbers found to redact.",
        "text": text,
    }


def validate_urls(text: str) -> Dict[str, Any]:
    """
    Output Guardrail 6: URL Validator
    Blocks responses containing IP-based URLs (e.g., http://192.168.1.1/login)
    or URLs ending with suspicious domain suffixes (.zip, .xyz, .tk, .ru, .click).
    """
    # 1. Check IP-based URLs
    ip_match = re.search(IP_URL_PATTERN, text, re.IGNORECASE)
    if ip_match:
        return {
            "name": "URL Validator",
            "status": "blocked",
            "message": f"Blocked unsafe response: contains IP-based URL ('{ip_match.group(0)}').",
            "text": text,
        }

    # 2. Find all URLs or domain references in text
    general_url_pattern = r"https?://[^\s<>\"'()]+|\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>\"'()]*)?"
    found_urls = re.findall(general_url_pattern, text)

    for url in found_urls:
        url_lower = url.lower()
        # Clean domain part
        domain = re.sub(r"^https?://", "", url_lower).split("/")[0].split(":")[0]
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return {
                    "name": "URL Validator",
                    "status": "blocked",
                    "message": f"Blocked unsafe response: contains URL with suspicious suffix '{tld}' ('{url}').",
                    "text": text,
                }

    return {
        "name": "URL Validator",
        "status": "passed",
        "message": "All URLs in the response passed safety validation.",
        "text": text,
    }


# ============================================================================
# PIPELINE RUNNERS
# ============================================================================

def run_input_guardrails(
    text: str,
    enabled_guardrails: Optional[Dict[str, bool]] = None
) -> List[Dict[str, Any]]:
    """
    Runs the 4 input guardrails in order:
      1. Word Count Limit
      2. Prompt Injection Detector
      3. PII Detector
      4. API Key Detector
    
    Stops at the first 'blocked' result.
    Optionally skips any guardrail disabled in `enabled_guardrails`.
    """
    if enabled_guardrails is None:
        enabled_guardrails = {}

    pipeline = [
        ("Word Count Limit", lambda t: check_word_count(t)),
        ("Prompt Injection Detector", lambda t: check_prompt_injection(t)),
        ("PII Detector", lambda t: check_pii(t)),
        ("API Key Detector", lambda t: check_api_keys(t)),
    ]

    results: List[Dict[str, Any]] = []

    for name, guardrail_fn in pipeline:
        # Check if user disabled this guardrail in sidebar
        if not enabled_guardrails.get(name, True):
            continue

        result = guardrail_fn(text)
        results.append(result)

        # Stop immediately if a guardrail blocked the message
        if result["status"] == "blocked":
            break

    return results


def run_output_guardrails(
    text: str,
    enabled_guardrails: Optional[Dict[str, bool]] = None
) -> List[Dict[str, Any]]:
    """
    Runs the 2 output guardrails in order:
      5. PII Redactor (updates text if modified)
      6. URL Validator (checks possibly redacted text)
    
    Stops at the first 'blocked' result.
    Optionally skips any guardrail disabled in `enabled_guardrails`.
    """
    if enabled_guardrails is None:
        enabled_guardrails = {}

    current_text = text
    results: List[Dict[str, Any]] = []

    # 5. PII Redactor
    if enabled_guardrails.get("PII Redactor", True):
        redact_res = redact_pii(current_text)
        results.append(redact_res)
        current_text = redact_res["text"]
        if redact_res["status"] == "blocked":
            return results

    # 6. URL Validator
    if enabled_guardrails.get("URL Validator", True):
        url_res = validate_urls(current_text)
        results.append(url_res)
        if url_res["status"] == "blocked":
            return results

    return results
