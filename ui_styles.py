"""
ui_styles.py
------------
Design system, CSS styling, and reusable presentation components
for SafeChat Gateway. Provides a modern, trustworthy, and calm security UI
supporting both Light and Dark modes seamlessly.
"""

import re
import textwrap
from typing import Optional

# ============================================================================
# DESIGN SYSTEM & CSS DEFINITIONS
# ============================================================================
CSS_STYLES = textwrap.dedent("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ==========================================================================
   CSS CUSTOM PROPERTIES (THEME-ADAPTIVE)
   ========================================================================== */
:root {
  --font-sans: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;

  /* Theme-adaptive colors derived from Streamlit's environment */
  --bg-main: var(--background-color, #F7F8FA);
  --bg-card: var(--secondary-background-color, #FFFFFF);
  --bg-card-alt: rgba(128, 128, 128, 0.08);
  --border-color: rgba(128, 128, 128, 0.22);
  --border-light: rgba(128, 128, 128, 0.12);
  --border-focus: #4F46E5;
  --text-main: var(--text-color, #111827);
  --text-muted: rgba(128, 128, 128, 0.95);

  /* Primary Brand */
  --primary: #4F46E5;
  --primary-hover: #4338CA;
  --primary-light: rgba(79, 70, 229, 0.14);
  --primary-border: rgba(79, 70, 229, 0.35);

  /* Semantic Status Colors */
  --status-pass-text: #16A34A;
  --status-pass-bg: rgba(22, 163, 74, 0.14);
  --status-pass-border: rgba(22, 163, 74, 0.32);

  --status-block-text: #DC2626;
  --status-block-bg: rgba(220, 38, 38, 0.14);
  --status-block-border: rgba(220, 38, 38, 0.32);

  --status-mod-text: #D97706;
  --status-mod-bg: rgba(217, 119, 6, 0.14);
  --status-mod-border: rgba(217, 119, 6, 0.32);

  --status-info-text: #2563EB;
  --status-info-bg: rgba(37, 99, 235, 0.14);
  --status-info-border: rgba(37, 99, 235, 0.32);

  --status-skip-text: rgba(128, 128, 128, 0.85);
  --status-skip-bg: rgba(128, 128, 128, 0.10);
  --status-skip-border: rgba(128, 128, 128, 0.20);

  /* Spacing, Radius, Shadows */
  --radius-sm: 6px;
  --radius-md: 8px;
  --radius-card: 12px;
  --radius-pill: 9999px;
  --shadow-subtle: 0 1px 3px rgba(0, 0, 0, 0.08);
  --shadow-card: 0 1px 4px rgba(0, 0, 0, 0.07);
}

/* Dark Mode Overrides */
@media (prefers-color-scheme: dark) {
  :root {
    --primary: #6366F1;
    --primary-hover: #818CF8;
    --primary-light: rgba(99, 102, 241, 0.22);
    --primary-border: rgba(99, 102, 241, 0.40);

    --status-pass-text: #4ADE80;
    --status-pass-bg: rgba(34, 197, 94, 0.18);
    --status-pass-border: rgba(34, 197, 94, 0.38);

    --status-block-text: #F87171;
    --status-block-bg: rgba(239, 68, 68, 0.18);
    --status-block-border: rgba(239, 68, 68, 0.38);

    --status-mod-text: #FBBF24;
    --status-mod-bg: rgba(245, 158, 11, 0.18);
    --status-mod-border: rgba(245, 158, 11, 0.38);

    --status-info-text: #60A5FA;
    --status-info-bg: rgba(59, 130, 246, 0.18);
    --status-info-border: rgba(59, 130, 246, 0.38);

    --text-muted: #94A3B8;
    --border-color: rgba(255, 255, 255, 0.14);
  }
}

/* ==========================================================================
   GLOBAL TYPOGRAPHY & CHROME REMOVAL
   ========================================================================== */
html, body, [class*="css"], .stMarkdown, .stText {
  font-family: var(--font-sans) !important;
  -webkit-font-smoothing: antialiased;
}

.block-container {
  padding-top: 1.25rem !important;
  padding-bottom: 2.5rem !important;
  max-width: 1440px !important;
}

#MainMenu { visibility: hidden !important; }
footer { visibility: hidden !important; }
.stDeployButton { display: none !important; }
header[data-testid="stHeader"] {
  background-color: transparent !important;
  height: 2rem !important;
}

/* Focus Rings & Transitions */
button, input, textarea {
  transition: all 150ms ease-in-out !important;
}
button:focus-visible, input:focus-visible, textarea:focus-visible {
  outline: 2px solid var(--border-focus) !important;
  outline-offset: 2px !important;
}

/* Sidebar Styling & Contrast */
[data-testid="stSidebar"] {
  border-right: 1px solid var(--border-color) !important;
}
[data-testid="stSidebar"] label p,
[data-testid="stSidebar"] .stMarkdown p,
[data-testid="stSidebar"] h3 {
  color: var(--text-main) !important;
}
[data-testid="stSidebar"] .stCaption p {
  color: var(--text-muted) !important;
}

/* Streamlit Tabs */
button[data-baseweb="tab"] {
  font-size: 13.5px !important;
  font-weight: 600 !important;
  color: var(--text-muted) !important;
  padding: 0.5rem 1rem !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
  color: var(--primary) !important;
  border-bottom: 2px solid var(--primary) !important;
}

/* ==========================================================================
   HEADER BANNER
   ========================================================================== */
.gateway-header {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-card);
  padding: 1.15rem 1.4rem;
  margin-bottom: 1.25rem;
  box-shadow: var(--shadow-card);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
}

.gateway-brand {
  display: flex;
  align-items: center;
  gap: 0.85rem;
}

.gateway-logo-icon {
  font-size: 2.2rem;
  line-height: 1;
}

.gateway-titles {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.gateway-title {
  font-size: 26px;
  font-weight: 800;
  letter-spacing: -0.025em;
  color: var(--text-main);
  margin: 0;
  line-height: 1.2;
}

.gateway-subtitle {
  font-size: 13.5px;
  color: var(--text-muted);
  margin: 0;
  font-weight: 400;
}

.gateway-status-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.35rem 0.85rem;
  border-radius: var(--radius-pill);
  font-size: 12px;
  font-weight: 600;
}

.status-pill-live {
  background: var(--status-pass-bg);
  color: var(--status-pass-text);
  border: 1px solid var(--status-pass-border);
}

.status-pill-missing {
  background: var(--status-mod-bg);
  color: var(--status-mod-text);
  border: 1px solid var(--status-mod-border);
}

.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  display: inline-block;
}

.dot-live {
  background-color: var(--status-pass-text);
  box-shadow: 0 0 6px var(--status-pass-text);
}

.dot-missing {
  background-color: var(--status-mod-text);
  box-shadow: 0 0 6px var(--status-mod-text);
}

/* ==========================================================================
   CHAT MESSAGES & BUBBLES
   ========================================================================== */
.message-row {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 1.1rem;
  width: 100%;
}

.message-row.user {
  justify-content: flex-end;
}

.message-row.assistant {
  justify-content: flex-start;
}

.avatar-badge {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 700;
  flex-shrink: 0;
}

.avatar-user {
  background: var(--primary);
  color: #FFFFFF;
}

.avatar-gateway {
  background: var(--bg-card);
  color: var(--text-main);
  border: 1px solid var(--border-color);
}

.message-bubble {
  max-width: 82%;
  padding: 0.85rem 1.1rem;
  font-size: 14px;
  line-height: 1.5;
  box-shadow: var(--shadow-subtle);
}

.message-bubble.user {
  background: var(--primary);
  color: #FFFFFF;
  border-radius: 14px 14px 4px 14px;
  word-break: break-word;
}

.message-bubble.assistant {
  background: var(--bg-card);
  color: var(--text-main);
  border: 1px solid var(--border-color);
  border-radius: 14px 14px 14px 4px;
  word-break: break-word;
}

/* Blocked Alert Card inside Assistant Bubble */
.blocked-card {
  background: var(--status-block-bg);
  border: 1px solid var(--status-block-border);
  border-left: 4px solid var(--status-block-text);
  border-radius: var(--radius-md);
  padding: 0.85rem 1rem;
  margin-top: 0.45rem;
}

.blocked-card-header {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-weight: 700;
  font-size: 13.5px;
  color: var(--status-block-text);
  margin-bottom: 0.35rem;
}

.blocked-card-body {
  font-size: 13px;
  color: var(--text-main);
  line-height: 1.45;
  margin-bottom: 0.5rem;
}

.blocked-card-tip {
  font-size: 12px;
  color: var(--text-muted);
  background: rgba(128, 128, 128, 0.1);
  border-radius: var(--radius-sm);
  padding: 0.35rem 0.55rem;
  border: 1px dashed var(--status-block-border);
}

/* File Attachment Chip */
.file-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: var(--bg-card-alt);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 0.4rem 0.75rem;
  margin-bottom: 0.45rem;
  font-size: 12.5px;
  color: var(--text-main);
}

.file-chip-icon {
  font-size: 14px;
}

.file-chip-name {
  font-weight: 600;
}

.file-chip-size {
  color: var(--text-muted);
  font-size: 11px;
}

/* ==========================================================================
   STATUS BADGES & VERDICT BANNERS
   ========================================================================== */
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 11.5px;
  font-weight: 700;
  padding: 0.2rem 0.55rem;
  border-radius: var(--radius-pill);
  letter-spacing: 0.03em;
  text-transform: uppercase;
  margin-bottom: 0.35rem;
}

.badge-passed {
  background: var(--status-pass-bg);
  color: var(--status-pass-text);
  border: 1px solid var(--status-pass-border);
}

.badge-blocked {
  background: var(--status-block-bg);
  color: var(--status-block-text);
  border: 1px solid var(--status-block-border);
}

.badge-modified {
  background: var(--status-mod-bg);
  color: var(--status-mod-text);
  border: 1px solid var(--status-mod-border);
}

.badge-skipped {
  background: var(--status-skip-bg);
  color: var(--status-skip-text);
  border: 1px solid var(--status-skip-border);
}

/* Verdict Summary Banner */
.verdict-banner {
  border-radius: var(--radius-card);
  padding: 0.95rem 1.15rem;
  margin-bottom: 1.1rem;
  border: 1px solid transparent;
  box-shadow: var(--shadow-subtle);
}

.banner-accepted {
  background: var(--status-pass-bg);
  border-color: var(--status-pass-border);
}

.banner-blocked {
  background: var(--status-block-bg);
  border-color: var(--status-block-border);
}

.banner-modified {
  background: var(--status-mod-bg);
  border-color: var(--status-mod-border);
}

.banner-title {
  font-size: 14px;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 0.45rem;
  margin-bottom: 0.2rem;
}

.banner-desc {
  font-size: 12.5px;
  color: var(--text-main);
  line-height: 1.4;
}

/* ==========================================================================
   VERTICAL TIMELINE & GUARDRAIL STEP CARDS
   ========================================================================== */
.timeline-section-title {
  font-size: 12.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  margin-top: 0.9rem;
  margin-bottom: 0.45rem;
  display: flex;
  align-items: center;
  gap: 0.45rem;
}

.step-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 0.65rem 0.85rem;
  margin-bottom: 0.5rem;
  box-shadow: var(--shadow-subtle);
}

.step-card-blocked {
  border-left: 4px solid var(--status-block-text) !important;
  background: var(--bg-card);
}

.step-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.2rem;
}

.step-name-row {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-weight: 600;
  font-size: 13px;
  color: var(--text-main);
}

.step-rule-code {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--text-muted);
  background: var(--border-light);
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
}

.step-message {
  font-size: 12px;
  color: var(--text-muted);
  line-height: 1.4;
}

.monospace-chip {
  font-family: var(--font-mono);
  font-size: 11px;
  background: var(--border-light);
  color: var(--status-block-text);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 0.1rem 0.35rem;
  margin-top: 0.25rem;
  display: inline-block;
}

/* ==========================================================================
   METRIC CARDS (STATS TAB)
   ========================================================================== */
.metric-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-card);
  padding: 0.85rem 1rem;
  box-shadow: var(--shadow-subtle);
  display: flex;
  flex-direction: column;
  margin-bottom: 0.6rem;
}

.metric-card-label {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.2rem;
}

.metric-card-value {
  font-family: var(--font-mono);
  font-size: 24px;
  font-weight: 800;
  line-height: 1.1;
}

/* ==========================================================================
   EMPTY STATE
   ========================================================================== */
.empty-state-wrapper {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 2.5rem 1.5rem 1.5rem 1.5rem;
  color: var(--text-muted);
}

.empty-state-icon {
  font-size: 3.5rem;
  line-height: 1;
  margin-bottom: 0.5rem;
}

.empty-state-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text-main);
  margin-bottom: 0.25rem;
}

.empty-state-subtitle {
  font-size: 13px;
  max-width: 360px;
  line-height: 1.45;
  margin-bottom: 1.25rem;
}

/* ==========================================================================
   RESPONSIVENESS
   ========================================================================== */
@media (max-width: 960px) {
  div[data-testid="column"] {
    width: 100% !important;
    flex: 1 1 100% !important;
    min-width: 100% !important;
    margin-bottom: 1.25rem;
  }
}
</style>
""").strip()


# ============================================================================
# REUSABLE UI HELPER FUNCTIONS
# ============================================================================

def render_header(api_connected: bool) -> str:
    """
    Renders the modern security product header with brand logo,
    clear title, subtitle, and live connection status pill.
    Never produces leading whitespace that Markdown could treat as code blocks.
    """
    if api_connected:
        pill_class = "status-pill-live"
        dot_class = "dot-live"
        pill_text = "Gemini Connected"
    else:
        pill_class = "status-pill-missing"
        dot_class = "dot-missing"
        pill_text = "API Key Missing (Testing Mode)"

    html = f"""<div class="gateway-header">
<div class="gateway-brand">
<div class="gateway-logo-icon">🛡️</div>
<div class="gateway-titles">
<h1 class="gateway-title">SafeChat Gateway</h1>
<p class="gateway-subtitle">A security guard at the door and a checker at the exit. Gemini is the helper inside.</p>
</div>
</div>
<div class="gateway-status-pill {pill_class}">
<span class="status-dot {dot_class}"></span>
<span>{pill_text}</span>
</div>
</div>"""
    return html


def render_badge(status: str, label: Optional[str] = None) -> str:
    """
    Renders an accessible status badge with both icon and text label.
    """
    st_clean = status.lower()
    if "pass" in st_clean:
        icon = "✅"
        badge_cls = "badge-passed"
        text = label or "Accepted"
    elif "block" in st_clean:
        icon = "⛔"
        badge_cls = "badge-blocked"
        text = label or "Blocked"
    elif "mod" in st_clean:
        icon = "✏️"
        badge_cls = "badge-modified"
        text = label or "Modified"
    else:
        icon = "○"
        badge_cls = "badge-skipped"
        text = label or "Skipped"

    return f'<span class="status-badge {badge_cls}"><span>{icon}</span><span>{text}</span></span>'


def render_verdict_banner(final_status: str, reason: str, stage_blocked: Optional[str] = None) -> str:
    """
    Renders a summary banner for the top of the Guardrail Log.
    """
    status_lower = final_status.lower()
    if "blocked" in status_lower:
        cls = "banner-blocked"
        stage_text = f" at {stage_blocked}" if stage_blocked else ""
        title = f"⛔ Result: Blocked{stage_text}"
    elif "change" in status_lower or "modified" in status_lower:
        cls = "banner-modified"
        title = "✏️ Result: Accepted with Changes"
    else:
        cls = "banner-accepted"
        title = "✅ Result: Accepted"

    html = f"""<div class="verdict-banner {cls}">
<div class="banner-title">{title}</div>
<div class="banner-desc">{reason}</div>
</div>"""
    return html


def mask_sensitive_text(text: str) -> str:
    """
    Partially masks sensitive data (phone, credit card, SSN, email, tokens)
    so it can be safely reviewed in the audit log chip without exposure.
    """
    if not text:
        return ""

    # Mask Phone Number: 555-123-4567 -> 555-***-4567
    phone_sub = re.sub(
        r"(\b\d{3})[-.\s]?(\d{3})[-.\s]?(\d{4}\b)",
        r"\1-***-\3",
        text
    )
    if phone_sub != text:
        return phone_sub

    # Mask Credit Card: 4111 1111 1111 1111 -> 4111 **** **** 1111
    cc_sub = re.sub(
        r"\b(\d{4})[ -]?\d{4}[ -]?\d{4}[ -]?(\d{4})\b",
        r"\1 **** **** \2",
        text
    )
    if cc_sub != text:
        return cc_sub

    # Mask SSN: 123-45-6789 -> ***-**-6789
    ssn_sub = re.sub(
        r"\b\d{3}-\d{2}-(\d{4})\b",
        r"***-**-\1",
        text
    )
    if ssn_sub != text:
        return ssn_sub

    # Mask Email: john.doe@example.com -> j***e@example.com
    def _mask_email(m):
        user, domain = m.group(1), m.group(2)
        if len(user) > 2:
            return f"{user[0]}***{user[-1]}@{domain}"
        return f"{user[0]}***@{domain}"

    email_sub = re.sub(
        r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
        _mask_email,
        text
    )
    if email_sub != text:
        return email_sub

    if len(text) > 16:
        return f"{text[:4]}***{text[-4:]}"
    return text


def get_policy_tip(policy_name: str) -> str:
    """
    Returns a short, helpful, plain-language tip advising what to change
    when a specific guardrail intercepts a request.
    """
    tips = {
        "Word Count Limit": "Tip: Shorten your question to focus on key points (limit: 100 words).",
        "Prompt Injection Detector": "Tip: Rephrase as a standard question without words like 'ignore rules' or 'system prompt'.",
        "PII Detector": "Tip: Remove personal identifiers (phone numbers, cards, or SSNs) before resubmitting.",
        "API Key Detector": "Tip: Remove exposed API keys or access tokens before submitting.",
        "File Type Check": "Tip: Upload an approved format (PDF, TXT, DOCX, PNG, JPG, JPEG).",
        "File Size Limit": "Tip: Choose a smaller file under 5 MB or compress your document.",
        "Real Type Check": "Tip: Ensure your file extension matches its true content signature.",
        "PDF Page Limit": "Tip: Split your PDF document into smaller sections under 10 pages.",
        "Metadata Cleaner": "Tip: EXIF metadata is automatically cleaned before transmission.",
        "PII Redactor": "Tip: Private contact details in responses are masked with [REDACTED].",
        "URL Validator": "Tip: Avoid IP addresses or suspicious domain extensions.",
    }
    return tips.get(policy_name, "Tip: Verify that your request satisfies Gateway safety rules.")


def render_blocked_alert(policy_name: str, reason: str, tip: str) -> str:
    """
    Renders a friendly, clean alert card explaining which guardrail blocked
    the request, why, and a one-line recommendation.
    """
    html = f"""<div class="blocked-card">
<div class="blocked-card-header">
<span>⛔ Security Gateway Intervention</span>
</div>
<div class="blocked-card-body">
<strong>{policy_name}</strong>: {reason}
</div>
<div class="blocked-card-tip">
{tip}
</div>
</div>"""
    return html


def render_timeline_step(
    name: str,
    rule_code: str,
    status: str,
    message: str,
    is_blocked_target: bool = False,
    caught_text: Optional[str] = None
) -> str:
    """
    Renders an individual timeline card for the Guardrail Log.
    Highlights blocking steps with a red left border and shows
    partially masked caught text in a monospace chip if present.
    """
    card_cls = "step-card-blocked" if is_blocked_target else "step-card"

    status_clean = status.lower()
    if status_clean == "passed":
        badge = '<span class="status-badge badge-passed">✅ PASSED</span>'
    elif status_clean == "blocked":
        badge = '<span class="status-badge badge-blocked">⛔ BLOCKED</span>'
    elif status_clean == "modified":
        badge = '<span class="status-badge badge-modified">✏️ MODIFIED</span>'
    elif status_clean == "off":
        badge = '<span class="status-badge badge-skipped">○ OFF</span>'
    else:
        badge = '<span class="status-badge badge-skipped">○ SKIPPED</span>'

    caught_chip_html = ""
    if caught_text:
        masked_val = mask_sensitive_text(caught_text)
        caught_chip_html = f'<div class="monospace-chip">Matched: {masked_val}</div>'

    html = f"""<div class="{card_cls}">
<div class="step-header">
<span class="step-name-row">
<span>{name}</span>
<span class="step-rule-code">{rule_code}</span>
</span>
{badge}
</div>
<div class="step-message">{message}</div>
{caught_chip_html}
</div>"""
    return html


def render_metric_card(label: str, value: int, accent_color: str) -> str:
    """
    Renders a clean metric card for the Stats tab with a designated accent color.
    """
    html = f"""<div class="metric-card" style="border-top: 3px solid {accent_color};">
<div class="metric-card-label" style="color: {accent_color};">{label}</div>
<div class="metric-card-value" style="color: {accent_color};">{value}</div>
</div>"""
    return html


def render_file_chip(filename: str, size_bytes: Optional[int] = None, is_image: bool = False) -> str:
    """
    Renders a file chip with an icon, filename, and size.
    """
    icon = "🖼️" if is_image else "📄"
    size_str = ""
    if size_bytes:
        if size_bytes > 1024 * 1024:
            size_str = f"({size_bytes / (1024 * 1024):.1f} MB)"
        else:
            size_str = f"({size_bytes / 1024:.1f} KB)"

    html = f"""<div class="file-chip">
<span class="file-chip-icon">{icon}</span>
<span class="file-chip-name">{filename}</span>
<span class="file-chip-size">{size_str}</span>
</div>"""
    return html


def render_empty_state_svg() -> str:
    """
    Renders a centered shield illustration and welcome message for the empty chat state.
    """
    html = """<div class="empty-state-wrapper">
<div class="empty-state-icon">🛡️</div>
<div class="empty-state-title">Security Perimeter Active</div>
<div class="empty-state-subtitle">Type a message or attach a document below to observe the 11 guardrail checks inspecting traffic in real time.</div>
</div>"""
    return html
