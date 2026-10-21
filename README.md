# 🛡️ SafeChat Gateway

**A security guard at the door and a checker at the exit. Gemini is the helper inside.**

An AI chatbot that checks every message before it reaches Gemini and every reply before the user sees it. A live Guardrail Log shows each check as ✅ passed, ⛔ blocked, or ✏️ modified.

```
User ──► Input Guardrails ──► Gemini ──► Output Guardrails ──► User
```

## Why

AI chatbots are not safe by default. Users can trick them, leak private data or API keys, and the AI can reply with sensitive data or risky links. This project adds simple checks on both sides.

## Guardrails

| Where | Guardrail | Action |
|---|---|---|
| Door | Word Count Limit (100 words) | Blocks long messages |
| Door | Prompt Injection Detector | Blocks "ignore your instructions" tricks |
| Door | PII Detector | Blocks SSNs, card and phone numbers |
| Door | API Key Detector | Blocks pasted keys and secrets |
| Exit | PII Redactor | Replaces emails and card numbers with `[REDACTED]` |
| Exit | URL Validator | Blocks IP-based and suspicious URLs |

## Tech Stack

Python 3.10+ · Streamlit · Gemini API (`google-genai`) · python-dotenv · Regex · pytest

## Project Structure

```
safechat-gateway/
├── app.py              # Streamlit UI
├── guardrails.py       # The 6 checks
├── gemini_client.py    # Gemini API call
├── test_guardrails.py  # Tests
├── requirements.txt
├── .env.example
└── .gitignore
```

## Run It

```bash
# 1. Install
pip install -r requirements.txt

# 2. Add your key: copy .env.example to .env, then edit it
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.5-flash

# 3. Start
streamlit run app.py
```

Open http://localhost:8501. Optional: run `pytest` to test the guardrails.

> Never share or upload your `.env` file.

## Demo

1. **Normal question:** answered, all checks pass ✅
2. **Try a trick:** blocked at the door ⛔
3. **Share private data:** blocked before reaching Gemini ⛔
4. **Test output redaction:** email replaced with `[REDACTED]` ✏️

## Limitations

Basic regex rules can miss attacks or block harmless text. This is a learning project, not a complete security solution.

## Future Work

ML-based detection · logging and admin dashboard · persistent rate limiting · more guardrails
