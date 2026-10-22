"""Streamlit dashboard for explainable phishing URL/message triage."""
import html
import re
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import urlencode

import streamlit as st

from detector import PhishingClassifier

st.set_page_config(page_title="PHISHintoASH | Message Scanner", page_icon="🛡️", layout="wide")

appearance = st.radio(
    "Appearance", ["Dark", "Light"], horizontal=True, key="appearance",
    label_visibility="collapsed",
)

LIGHT_THEME_CSS = """
:root { color-scheme:light; --ink:#182b3d; --muted:#62768b; --accent:#2463eb; --line:rgba(62,99,151,.2); --glass:rgba(255,255,255,.52); --glass-bright:rgba(255,255,255,.8); }
.stApp,[data-testid="stAppViewContainer"],[data-testid="stMain"],.main { background:radial-gradient(ellipse at 10% 0%,rgba(72,139,255,.27),transparent 38%),radial-gradient(ellipse at 92% 42%,rgba(119,178,255,.24),transparent 34%),radial-gradient(ellipse at 58% 100%,rgba(173,201,255,.2),transparent 42%),linear-gradient(145deg,#e7f0ff 0%,#f9fbff 52%,#e5efff 100%)!important;color:var(--ink); }
.hero { background:linear-gradient(115deg,rgba(255,255,255,.58),rgba(235,244,255,.48));box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 18px 55px rgba(35,77,140,.1); }
.hero:after { background:rgba(36,99,235,.10); }
.hero h1,.section-label,.panel-title,.risk-title { color:#152b43; }
.hero p { color:#5a6f85; }
.risk-card [style*="color:#f1f7fb"],.risk-card [style*="color:#dbe7ef"] { color:#152b43!important; }
.shield { border-color:rgba(36,99,235,.2);background:rgba(36,99,235,.07); }
.panel,.risk-card { background:linear-gradient(145deg,rgba(255,255,255,.62),rgba(239,246,255,.52));box-shadow:inset 0 1px 0 rgba(255,255,255,.85),0 16px 45px rgba(33,65,110,.1); }
.status-pill { border-color:rgba(36,99,235,.2);color:#2355b7;background:rgba(36,99,235,.06); }
.gauge:before { background:rgba(255,255,255,.78);border-color:rgba(62,99,151,.18); }
.gauge-value,.mini-value { color:#182b3d; }
.mini { background:rgba(255,255,255,.46);border-color:rgba(62,99,151,.15); }
.indicator { color:#344b62;background:linear-gradient(110deg,rgba(255,255,255,.62),rgba(235,243,255,.4));border-color:rgba(62,99,151,.17); }
.empty-state { color:#657b91; }
.stTextArea label,.stSelectbox label { color:#243d56!important; }
.stTextArea textarea,[data-testid="stTextArea"] textarea,div[data-baseweb="textarea"] textarea { color:#182b3d!important;background:#f8fbff!important;background-color:#f8fbff!important;border:1px solid rgba(62,99,151,.28)!important;caret-color:#2463eb!important;box-shadow:inset 0 1px 5px rgba(44,77,125,.05),0 8px 24px rgba(40,80,145,.08)!important; }
.stTextArea textarea::placeholder,[data-testid="stTextArea"] textarea::placeholder { color:#7589a1!important;opacity:1!important; }
.stSelectbox [data-baseweb="select"],.stSelectbox [data-baseweb="select"]>div,.stSelectbox [data-baseweb="select"] input { background:#f8fbff!important;background-color:#f8fbff!important;color:#182b3d!important;border-color:rgba(62,99,151,.28)!important; }
[data-baseweb="popover"],[data-baseweb="menu"],[role="listbox"] { background:#fff!important;color:#182b3d!important; }
[role="option"] { color:#182b3d!important; }
.stButton>button { background:linear-gradient(115deg,rgba(36,89,215,.94),rgba(67,133,255,.84));color:#fff;box-shadow:inset 0 1px 0 rgba(255,255,255,.6),0 10px 25px rgba(36,99,235,.2); }
.stButton>button:hover { color:#fff; }
div[data-testid="stExpander"] { background:rgba(255,255,255,.48); }
.footer-note { color:#637a91; }
"""

def get_contact_email() -> str:
    """Read the contact destination from private Streamlit configuration."""
    try:
        return str(st.secrets.get("contact_email", "")).strip()
    except Exception:
        return ""

CONTACT_EMAIL = get_contact_email()

def gmail_compose_url(subject: str, body: str = "") -> str:
    """Build a Gmail compose URL so browsers without a mailto handler still work."""
    query = urlencode({"view": "cm", "fs": "1", "to": CONTACT_EMAIL,
                       "su": subject, "body": body})
    return f"https://mail.google.com/mail/?{query}"

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { color-scheme:dark; --ink:#e9f1f8; --muted:#91a4b7; --accent:#ff4057; --line:rgba(205,223,242,.2); --glass:rgba(19,31,46,.48); --glass-bright:rgba(255,255,255,.09); }
.stApp { background:radial-gradient(ellipse at 10% 4%,rgba(255,64,87,.22),transparent 34%),radial-gradient(ellipse at 86% 42%,rgba(60,105,158,.22),transparent 36%),radial-gradient(ellipse at 54% 102%,rgba(112,63,118,.16),transparent 43%),linear-gradient(145deg,#08121d 0%,#0b1723 50%,#101d2c 100%); color:var(--ink); font-family:'Manrope',sans-serif; }
[data-testid="stAppViewContainer"],[data-testid="stMain"],.main { background:transparent!important; }
[data-testid="stHeader"] { background:transparent; }
[data-testid="stToolbar"] { right:1.5rem; }
[data-testid="stMainBlockContainer"] { max-width:1180px; padding-top:2.2rem; padding-bottom:4rem; }
.stRadio [role="radiogroup"] { display:inline-flex;gap:5px;padding:5px;border:1px solid var(--line);border-radius:999px;background:var(--glass);backdrop-filter:blur(16px); }
.stRadio [role="radiogroup"] label { border-radius:999px;padding:5px 13px;color:var(--muted);font-size:12px; }
.stRadio [role="radiogroup"] label:has(input:checked) { background:var(--accent);color:#fff;box-shadow:0 3px 12px color-mix(in srgb,var(--accent) 30%,transparent); }
.block-container { animation: enter .65s ease-out both; }
@keyframes enter { from {opacity:0; transform:translateY(12px)} to {opacity:1; transform:translateY(0)} }
@keyframes glow { 0%,100% {box-shadow:0 0 20px rgba(255,64,87,.1)} 50% {box-shadow:0 0 38px rgba(255,64,87,.25)} }
@keyframes drift { 0%,100% {transform:translateY(0)} 50% {transform:translateY(-7px)} }
.hero { position:relative; isolation:isolate; overflow:hidden; border:1px solid var(--line); border-radius:26px; padding:31px 36px; margin:0 0 25px; background:linear-gradient(115deg,rgba(65,35,50,.48),rgba(22,39,58,.48));box-shadow:inset 0 1px 0 rgba(255,255,255,.16),0 18px 55px rgba(0,0,0,.16);backdrop-filter:blur(24px) saturate(155%);-webkit-backdrop-filter:blur(24px) saturate(155%); }
.hero:before,.panel:before,.risk-card:before { content:'';position:absolute;inset:0;pointer-events:none;border-radius:inherit;background:linear-gradient(128deg,rgba(255,255,255,.12),transparent 28%,transparent 68%,rgba(255,255,255,.025)); }
.hero:after { content:''; position:absolute; z-index:-1;width:290px;height:290px; right:8%;top:-185px;border-radius:50%;background:rgba(255,64,87,.2);filter:blur(48px); }
.eyebrow { color:var(--accent); font:500 11px 'DM Mono',monospace; letter-spacing:2px; text-transform:uppercase; margin-bottom:12px; }
.hero h1 { color:#f1f7fb; font-size:clamp(30px,4vw,47px); line-height:1.08; letter-spacing:-2px; margin:0 0 12px; font-weight:800; }
.hero p { color:#a7b9c9; font-size:15px; line-height:1.65; max-width:680px; margin:0; }
.shield { float:right; width:68px;height:68px;display:grid;place-items:center;border:1px solid rgba(255,64,87,.28);border-radius:22px;background:rgba(255,64,87,.08);font-size:32px;animation:drift 4s ease-in-out infinite; }
.section-label { color:#dce8f1; font-size:18px; font-weight:700; margin:4px 0 4px; }
.section-hint { color:var(--muted);font-size:13px;margin:0 0 16px; }
.panel { position:relative;isolation:isolate;overflow:hidden;border:1px solid var(--line);border-radius:20px;padding:23px 25px;background:linear-gradient(145deg,rgba(30,48,67,.57),rgba(12,25,39,.54));box-shadow:inset 0 1px 0 rgba(255,255,255,.12),0 16px 45px rgba(0,0,0,.15);backdrop-filter:blur(22px) saturate(150%);-webkit-backdrop-filter:blur(22px) saturate(150%); }
.panel-title { color:#f1f7fb;font-size:16px;font-weight:700;margin:0 0 3px; }
.panel-copy { color:var(--muted);font-size:12px;margin:0 0 16px; }
.status-pill { display:inline-flex;align-items:center;gap:8px;border:1px solid rgba(255,64,87,.23);border-radius:999px;padding:7px 11px;color:#ffd1d6;background:rgba(255,64,87,.07);font:11px 'DM Mono',monospace; }
.status-dot { width:7px;height:7px;background:var(--accent);border-radius:50%;box-shadow:0 0 10px var(--accent); }
.risk-card { position:relative;isolation:isolate;overflow:hidden;border:1px solid var(--line);border-radius:22px;background:linear-gradient(145deg,rgba(30,46,64,.62),rgba(12,24,38,.62));padding:26px;animation:glow 3.8s ease-in-out infinite;box-shadow:inset 0 1px 0 rgba(255,255,255,.14),0 18px 55px rgba(0,0,0,.18);backdrop-filter:blur(24px) saturate(155%);-webkit-backdrop-filter:blur(24px) saturate(155%); }
.risk-head { display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px; }
.risk-title { color:#f1f7fb;font-size:16px;font-weight:700; }
.risk-tag { border-radius:99px;padding:7px 11px;font:11px 'DM Mono',monospace;letter-spacing:.3px; }
.gauge-wrap { display:flex;align-items:center;justify-content:center;padding:8px 0 22px; }
.gauge { width:196px;height:196px;border-radius:50%;display:grid;place-items:center;position:relative; }
.gauge:before { content:'';position:absolute;inset:12px;border-radius:50%;background:rgba(13,25,39,.78);border:1px solid rgba(205,223,242,.18);box-shadow:inset 0 2px 12px rgba(255,255,255,.06);backdrop-filter:blur(12px); }
.gauge-center { position:relative;text-align:center; }
.gauge-value { color:#f4f8fb;font:700 48px 'DM Mono',monospace;letter-spacing:-3px;line-height:1; }
.gauge-unit { color:#9eb0c0;font:11px 'DM Mono',monospace;margin-top:6px;letter-spacing:1px;text-transform:uppercase; }
.mini-grid { display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:8px; }
.mini { border:1px solid rgba(205,223,242,.14);border-radius:14px;padding:12px 10px;background:rgba(8,19,32,.3);box-shadow:inset 0 1px 0 rgba(255,255,255,.08);backdrop-filter:blur(14px); }
.mini-label { color:#8196a9;font:9px 'DM Mono',monospace;letter-spacing:.8px;text-transform:uppercase;margin-bottom:7px; }
.mini-value { color:#dfeaf2;font:600 16px 'DM Mono',monospace; }
.indicator { display:flex;gap:11px;align-items:flex-start;border:1px solid rgba(205,223,242,.15);border-radius:14px;background:linear-gradient(110deg,rgba(255,255,255,.075),rgba(255,255,255,.025));box-shadow:inset 0 1px 0 rgba(255,255,255,.08);backdrop-filter:blur(16px);padding:12px 13px;margin:8px 0;color:#c6d4df;font-size:13px;line-height:1.45; }
.indicator-mark { color:#ffbc6b;font-size:15px;line-height:1.2; }
.empty-state { text-align:center;padding:36px 16px;color:#8fa4b7; }
.empty-icon { font-size:28px;margin-bottom:10px;opacity:.85; }
.stTextArea label,.stSelectbox label { color:#d8e5ed!important;font-weight:600!important;font-size:13px!important; }
.stTextArea textarea { background:rgba(9,22,36,.56)!important;color:#e9f1f8!important;border:1px solid rgba(205,223,242,.2)!important;border-radius:15px!important;line-height:1.6!important;backdrop-filter:blur(18px);box-shadow:inset 0 1px 0 rgba(255,255,255,.08),0 10px 25px rgba(0,0,0,.08)!important; }
.stTextArea textarea:focus { border-color:var(--accent)!important;box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 16%,transparent)!important; }
.stSelectbox [data-baseweb="select"]>div { background:rgba(9,22,36,.56);border-color:rgba(205,223,242,.22);border-radius:13px;color:#e9f1f8;backdrop-filter:blur(18px);box-shadow:inset 0 1px 0 rgba(255,255,255,.08); }
.stButton>button { background:linear-gradient(115deg,rgba(240,45,72,.94),rgba(255,105,125,.82));border:1px solid rgba(255,255,255,.28);border-radius:14px;color:#fff;font-weight:800;min-height:49px;box-shadow:inset 0 1px 0 rgba(255,255,255,.35),0 10px 25px rgba(255,64,87,.18);backdrop-filter:blur(12px);transition:transform .18s ease,filter .18s ease; }
.stButton>button:hover { filter:brightness(1.08);transform:translateY(-2px);color:#fff; }
[data-testid="stAlert"] { border-radius:13px; }
div[data-testid="stExpander"] { border:1px solid var(--line);border-radius:15px;background:var(--glass);box-shadow:inset 0 1px 0 rgba(255,255,255,.09);backdrop-filter:blur(18px); }
.footer-note { color:#73889a;font-size:11px;line-height:1.6;text-align:center;margin:25px auto 0;max-width:760px; }
.contact-card { border:1px solid var(--line);border-radius:20px;padding:22px 24px;margin-top:28px;background:var(--glass);box-shadow:inset 0 1px 0 rgba(255,255,255,.1);backdrop-filter:blur(20px); }
.contact-email { color:var(--accent);font-family:'DM Mono',monospace;font-size:14px; }
.feedback-link { display:inline-block;padding:11px 17px;border-radius:12px;background:var(--accent);color:#fff!important;text-decoration:none!important;font-weight:700; }
.contact-hint { color:var(--muted);font-size:12px;line-height:1.6; }
/*THEME_OVERRIDE*/
@media (max-width:700px) { .hero {padding:25px 22px}.shield{width:48px;height:48px;font-size:23px;border-radius:16px}.panel,.risk-card{padding:19px}.mini-grid{gap:6px}.mini{padding:10px 7px}.mini-value{font-size:14px} }
@media (prefers-reduced-motion: reduce) { *,*::before,*::after {animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important} }
</style>
""".replace("/*THEME_OVERRIDE*/", LIGHT_THEME_CSS if appearance == "Light" else ""), unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <div class="shield">🛡️</div>
  <div class="eyebrow">Personal Security Lab&nbsp; / &nbsp;Message Intelligence</div>
  <h1>PHISH<span style="color:var(--accent)">intoASH</span></h1>
  <p>Inspect suspicious links and messages with explainable signals. See what raised the score, then make a safer decision.</p>
</div>
""", unsafe_allow_html=True)

@st.cache_resource
def load_detector():
    return PhishingClassifier()

detector = load_detector()

left, right = st.columns([1.06, 0.94], gap="large")
with left:
    st.markdown('<div class="section-label">Run a quick scan</div><div class="section-hint">Paste a URL or message. Your text is analyzed locally by this demo.</div>', unsafe_allow_html=True)
    st.markdown('<div class="panel"><div class="panel-title">Analysis input</div><div class="panel-copy">Links, emails, SMS messages, or other suspicious text</div>', unsafe_allow_html=True)
    sample = st.selectbox("Load a sample", ["Choose an example…", "Benign email", "Suspicious email", "Suspicious URL"])
    samples = {
        "Benign email": "Your library book is due next Tuesday. Renew it online if needed.",
        "Suspicious email": "Immediate action required: verify your account now to avoid suspension. Click here to sign in.",
        "Suspicious URL": "http://secure-account-help.xyz/verify/login",
    }
    content = st.text_area("Message or URL", value=samples.get(sample, ""), height=190,
                           placeholder="Example: https://example.com or paste message text", label_visibility="collapsed")
    analyze = st.button("✦  Analyze for threats", type="primary", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<div style="height:16px"></div>', unsafe_allow_html=True)
    if detector.model is None:
        st.warning("Text model not found. In the project terminal, run `python model_trainer.py`.")
    else:
        st.markdown('<div class="status-pill"><span class="status-dot"></span> HEURISTICS + ML MODEL READY</div>', unsafe_allow_html=True)

with right:
    st.markdown('<div class="section-label">Threat assessment</div><div class="section-hint">Risk estimate and the signals behind it</div>', unsafe_allow_html=True)
    if analyze:
        try:
            result = detector.analyze(content)
            score = result["risk_score"]
            classification = result["classification"]
            if score >= 70:
                accent, tint, icon = "#ff7185", "rgba(255,113,133,.12)", "HIGH RISK"
            elif score >= 35:
                accent, tint, icon = "#ffbd68", "rgba(255,189,104,.12)", "CAUTION"
            else:
                accent, tint, icon = "#45e0bd", "rgba(69,224,189,.12)", "LOW RISK"
            safe_class = html.escape(classification)
            gauge = f"background:conic-gradient({accent} {score}%,rgba(164,190,213,.12) {score}% 100%);"
            st.markdown(f"""
            <div class="risk-card" style="--risk:{accent}">
              <div class="risk-head"><div class="risk-title">Scan result</div><span class="risk-tag" style="color:{accent};background:{tint};border:1px solid {accent}44">{icon}</span></div>
              <div style="color:#f1f7fb;font-size:21px;font-weight:800;text-align:center;margin:0 0 5px">{safe_class}</div>
              <div class="gauge-wrap"><div class="gauge" style="{gauge}"><div class="gauge-center"><div class="gauge-value">{score:g}</div><div class="gauge-unit">Risk score / 100</div></div></div></div>
              <div class="mini-grid">
                <div class="mini"><div class="mini-label">URL signals</div><div class="mini-value">{result['details']['url_risk']:g}<span style="color:#7e92a5;font-size:10px"> /100</span></div></div>
                <div class="mini"><div class="mini-label">Message clues</div><div class="mini-value">{result['details']['heuristic_risk']:g}<span style="color:#7e92a5;font-size:10px"> /100</span></div></div>
                <div class="mini"><div class="mini-label">Model signal</div><div class="mini-value">{result['details']['model_risk']:g}<span style="color:#7e92a5;font-size:10px">%</span></div></div>
              </div>
            </div>
            """, unsafe_allow_html=True)
            indicators = result["indicators"]
            st.markdown('<div style="height:14px"></div><div class="panel-title">Signals detected <span style="color:#8499aa;font:12px \'DM Mono\',monospace">(' + str(len(indicators)) + ')</span></div>', unsafe_allow_html=True)
            if indicators:
                for indicator in indicators:
                    st.markdown(f'<div class="indicator"><span class="indicator-mark">◆</span><span>{html.escape(indicator)}</span></div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="empty-state"><div class="empty-icon">✓</div>No configured warning signals found.<br>That does not guarantee the message is safe.</div>', unsafe_allow_html=True)
            with st.expander("How to read this score"):
                st.write("The score combines URL checks, message heuristics, and (when available) the text model. It is an estimate, not a calibrated probability.")
                st.json(result["details"])
        except ValueError as error:
            st.error(str(error))
    else:
        st.markdown("""
        <div class="risk-card" style="min-height:360px;display:flex;align-items:center;justify-content:center">
          <div class="empty-state"><div class="empty-icon" style="font-size:38px">⌁</div>
            <div style="color:#dbe7ef;font-size:16px;font-weight:700;margin-bottom:7px">Ready when you are</div>
            <div style="max-width:260px;margin:auto;line-height:1.6">Choose a sample or paste something suspicious, then start your scan.</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

if CONTACT_EMAIL:
    contact_url = html.escape(gmail_compose_url("PHISHintoASH contact"), quote=True)
    contact_action = f'<a class="feedback-link" href="{contact_url}" target="_blank" rel="noopener noreferrer">Contact me by email ↗</a>'
else:
    contact_action = '<span class="contact-hint">Set contact_email in .streamlit/secrets.toml to enable this link.</span>'
st.markdown(f'''
<div class="contact-card">
  <div class="panel-title">Share feedback or get in touch</div>
  <div class="contact-hint">Have an idea, found an issue, or want to discuss the project? Use the link below to open an email addressed to me.</div>
  {contact_action}
</div>
''', unsafe_allow_html=True)

def send_feedback_email(name: str, reply_email: str, feedback_text: str) -> bool:
    """Send feedback using SMTP values stored in Streamlit secrets."""
    try:
        smtp_settings = st.secrets.get("smtp", {})
    except Exception:
        # No local secrets file is normal; the caller then offers a mailto fallback.
        return False
    required = ("host", "port", "username", "password", "from_email")
    if not CONTACT_EMAIL or not all(smtp_settings.get(key) for key in required):
        return False

    message = EmailMessage()
    message["Subject"] = "PHISHintoASH feedback"
    message["From"] = smtp_settings["from_email"]
    message["To"] = CONTACT_EMAIL
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", reply_email.strip()):
        message["Reply-To"] = reply_email.strip()
    sender = name.strip() or "Not provided"
    message.set_content(f"Feedback for PHISHintoASH\n\nFrom: {sender}\nReply email: {reply_email.strip() or 'Not provided'}\n\n{feedback_text.strip()}")

    port = int(smtp_settings["port"])
    context = ssl.create_default_context()
    if smtp_settings.get("use_ssl", False):
        with smtplib.SMTP_SSL(smtp_settings["host"], port, context=context, timeout=20) as server:
            server.login(smtp_settings["username"], smtp_settings["password"])
            server.send_message(message)
    else:
        with smtplib.SMTP(smtp_settings["host"], port, timeout=20) as server:
            server.starttls(context=context)
            server.login(smtp_settings["username"], smtp_settings["password"])
            server.send_message(message)
    return True

with st.form("feedback_form", clear_on_submit=False):
    sender_name = st.text_input("Your name (optional)", placeholder="How should I address you?")
    sender_email = st.text_input("Your email (optional)", placeholder="For a reply")
    feedback = st.text_area("Feedback", placeholder="Write your feedback or question…", height=110)
    send_feedback = st.form_submit_button("Prepare feedback email", use_container_width=True)

if send_feedback:
    if not feedback.strip():
        st.warning("Please write a short message before preparing the email.")
    else:
        try:
            if send_feedback_email(sender_name, sender_email, feedback):
                st.success("Thanks! Your feedback was emailed successfully.")
            else:
                message = f"Feedback for PHISHintoASH\n\nFrom: {sender_name.strip() or 'Not provided'}"
                if sender_email.strip():
                    message += f" ({sender_email.strip()})"
                message += f"\n\n{feedback.strip()}"
                email_url = html.escape(gmail_compose_url("PHISHintoASH feedback", message), quote=True)
                st.markdown(
                    f'<a class="feedback-link" href="{email_url}" target="_blank" rel="noopener noreferrer">Open feedback draft in Gmail ↗</a>',
                    unsafe_allow_html=True,
                )
                st.caption("Gmail opens a draft with the recipient and message filled in. Review it and press Send. To deliver feedback automatically from this app, configure SMTP as described in README.md.")
        except Exception:
            st.error("Feedback could not be sent. Check the SMTP settings in .streamlit/secrets.toml and try again.")

st.markdown('<div class="footer-note">For learning and defensive triage. This tool does not visit links or prove that a message is safe. Never enter passwords or confidential content. Verify unexpected requests using a trusted contact method.</div>', unsafe_allow_html=True)
