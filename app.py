import json
import re
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(page_title="PhishTrace", page_icon="🛡️", layout="wide")

SUSPICIOUS_WORDS = {
    "verify": 10,
    "urgent": 10,
    "login": 6,
    "password": 10,
    "account": 5,
    "suspended": 12,
    "bank": 5,
    "payment": 6,
    "prize": 10,
    "winner": 10,
    "free": 4,
    "update": 4,
    "confirm": 6,
    "security alert": 10,
    "click here": 8,
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at"
}

def normalize_url(raw_url):
    """Add a scheme for parsing when a user enters a bare domain."""
    candidate = raw_url.strip()
    if not candidate:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "http://" + candidate
    return candidate

def analyze_text(text, mode="URL"):
    """Rule-based triage only. It does not contact the URL or prove maliciousness."""
    findings = []
    score = 0
    raw = text.strip()

    if not raw:
        return {
            "input": text,
            "mode": mode,
            "risk_score": 0,
            "risk_level": "No input",
            "findings": ["Enter a URL or email text to analyse."],
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "disclaimer": "Rule-based educational triage; not a definitive verdict."
        }

    if mode == "URL":
        candidate = normalize_url(raw)
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            findings.append("Could not identify a hostname. Check whether the URL is written correctly.")
            score += 10
        else:
            findings.append(f"Hostname identified: {host}")

        if parsed.scheme.lower() == "https":
            findings.append("HTTPS is present. This protects data in transit but does not prove the site is trustworthy.")
        elif parsed.scheme.lower() == "http":
            findings.append("HTTP is used without TLS protection for the connection.")
            score += 10

        if "@" in parsed.netloc:
            findings.append("The URL contains '@' in its authority section, which can be used to disguise the destination.")
            score += 20

        if host and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            try:
                ipaddress.ip_address(host)
                findings.append("The hostname is an IPv4 address rather than a typical domain name.")
                score += 15
            except ValueError:
                pass

        if host.count(".") >= 3:
            findings.append("The hostname has several subdomain levels. This can be legitimate, but check the registered domain carefully.")
            score += 8

        if len(candidate) > 100:
            findings.append("The URL is unusually long.")
            score += 8

        if "-" in host:
            findings.append("The hostname contains hyphens. This is not automatically malicious, but deserves review.")
            score += 5

        if host in SHORTENER_DOMAINS:
            findings.append("The domain is a known URL-shortening service, so the final destination is not visible from the shortened link alone.")
            score += 15

        combined = candidate.lower()
    else:
        combined = raw.lower()
        findings.append("Email text was checked for common social-engineering warning signs.")
        if re.search(r"\b(from|sender)\s*:\s*.*@", raw, re.IGNORECASE):
            findings.append("A sender address appears in the text. Verify the full sender domain independently.")

    for word, points in SUSPICIOUS_WORDS.items():
        if word in combined:
            findings.append(f"Suspicious term or phrase found: “{word}” (+{points}).")
            score += points

    score = min(score, 100)
    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    if not findings:
        findings.append("No configured warning signs were detected. This does not mean the input is safe.")

    return {
        "input": raw,
        "mode": mode,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "Educational rule-based triage only. This score is not a probability, "
            "does not confirm whether content is malicious, and may produce false positives or false negatives."
        )
    }

st.title("🛡️ PhishTrace")
st.subheader("Smart Phishing Investigation & Reporting System")
st.write("Check common warning signs in a URL or email text, understand the reasons, and export a report.")

with st.sidebar:
    st.header("About this project")
    st.write("A beginner-friendly defensive cybersecurity prototype.")
    st.markdown("**Analysis method:** transparent rules")
    st.markdown("**Network requests:** none")
    st.markdown("**Privacy:** input is analysed locally by this app; do not paste real passwords or private messages.")
    st.caption("Version 1.0 — educational use")

mode = st.radio("What would you like to analyse?", ["URL", "Email text"], horizontal=True)
if mode == "URL":
    user_input = st.text_area(
        "Paste a suspicious URL",
        placeholder="Example: http://account-verify.example.com/login",
        height=100
    )
else:
    user_input = st.text_area(
        "Paste sample email text (remove private information)",
        placeholder="Example: URGENT! Your account is suspended. Click here to verify your password.",
        height=150
    )

col1, col2 = st.columns([1, 1])
with col1:
    analyze_button = st.button("Analyse input", type="primary", use_container_width=True)
with col2:
    clear_note = st.caption("Tip: use the built-in examples below for your first test.")

with st.expander("Try safe sample inputs"):
    st.code("http://account-verify.example.com/login")
    st.code("URGENT! Your account is suspended. Click here to verify your password.")
    st.code("https://www.example.com/")

if analyze_button:
    if not user_input.strip():
        st.warning("Please enter some text before analysing.")
    else:
        result = analyze_text(user_input, mode)
        st.session_state["last_result"] = result

if "last_result" in st.session_state:
    result = st.session_state["last_result"]
    st.divider()
    st.header("Investigation results")
    metric1, metric2 = st.columns(2)
    metric1.metric("Rule-based risk score", f'{result["risk_score"]}/100')
    metric2.metric("Risk category", result["risk_level"])

    if result["risk_level"] == "High":
        st.error("High warning level — investigate carefully.")
    elif result["risk_level"] == "Medium":
        st.warning("Medium warning level — review the findings.")
    elif result["risk_level"] == "Low":
        st.success("Low warning level — no strong configured signals were found.")
    else:
        st.info("No analysis was performed.")

    st.subheader("Findings")
    for finding in result["findings"]:
        st.write(f"• {finding}")

    st.info(result["disclaimer"])
    report_json = json.dumps(result, indent=2, ensure_ascii=False)
    st.download_button(
        "Download investigation report (JSON)",
        data=report_json,
        file_name="phishtrace_report.json",
        mime="application/json",
        use_container_width=True
    )

st.divider()
st.caption("PhishTrace is a learning project. Do not rely on its score alone to decide whether a website or email is safe.")

import re
import json
import ipaddress
from urllib.parse import urlparse, unquote

import streamlit as st

st.set_page_config(
    page_title="PhishTrace | Security Lab",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ PhishTrace")
st.subheader("Smart Phishing Investigation & Reporting System")
st.caption("Educational security analysis • Rule-based detection")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at"
}

SUSPICIOUS_WORDS = {
    "verify", "login", "password", "urgent", "suspended",
    "account", "free prize", "claim now", "bank details",
    "confirm identity", "one-time password", "otp"
}


def analyze_text(text):
    findings = []
    score = 0
    decoded = unquote(text.strip())
    lowered = decoded.lower()

    # Look for URLs in the submitted text.
    urls = re.findall(r'https?://[^\s<>"\']+', decoded, re.I)

    for raw_url in urls:
        url = raw_url.rstrip(".,;!?)")
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()

            if not host:
                continue

            try:
                ipaddress.ip_address(host)
                findings.append(
                    f"URL uses an IP address instead of a domain: {host}"
                )
                score += 20
            except ValueError:
                pass

            if host in SHORTENERS:
                findings.append(f"URL uses a known shortening service: {host}")
                score += 15

            if "xn--" in host:
                findings.append("URL contains an internationalized/punycode domain")
                score += 15

            if host.count(".") >= 4:
                findings.append("URL contains an unusually deep subdomain structure")
                score += 10

            if "@" in parsed.netloc:
                findings.append("URL contains an @ symbol in its authority section")
                score += 20

            if parsed.scheme.lower() != "https":
                findings.append("URL does not use HTTPS")
                score += 5

            if len(url) > 100:
                findings.append("URL is unusually long")
                score += 10

            if re.search(r"%[0-9a-fA-F]{2}", url):
                findings.append("URL contains percent-encoded characters")
                score += 5

        except ValueError:
            findings.append("A URL could not be parsed reliably")
            score += 5

    # Check for social-engineering language.
    for word in sorted(SUSPICIOUS_WORDS, key=len, reverse=True):
        if word in lowered:
            findings.append(f"Potential social-engineering term detected: '{word}'")
            score += 8

    if not urls:
        findings.append("No complete HTTP/HTTPS URL found in the submitted text")

    if not findings:
        findings.append("No configured warning signs were detected")

    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_score": score,
        "risk_level": level,
        "findings": list(dict.fromkeys(findings)),
        "urls_found": urls,
    }


st.info(
    "Use fictional examples only. This tool does not visit submitted URLs "
    "or prove whether a message is malicious."
)

sample = (
    "URGENT: Verify your password now at "
    "http://192.0.2.10/account-login to avoid suspension."
)

user_text = st.text_area(
    "Paste a suspicious URL or email/message text",
    height=160,
    placeholder="Paste the text you want to examine...",
)

col1, col2 = st.columns(2)

with col1:
    analyze_button = st.button("🔎 Analyze", type="primary", use_container_width=True)

with col2:
    sample_button = st.button("Load sample", use_container_width=True)

if sample_button:
    st.session_state["sample_text"] = sample
    st.rerun()

if "sample_text" in st.session_state and not user_text:
    st.caption("Sample loaded — copy it into the text area to analyze it.")

if analyze_button:
    if not user_text.strip():
        st.warning("Please enter some text to analyze.")
    else:
        report = analyze_text(user_text)

        st.divider()
        st.header("Investigation Results")

        c1, c2 = st.columns(2)
        c1.metric("Risk score", f'{report["risk_score"]}/100')
        c2.metric("Risk level", report["risk_level"])

        if report["risk_level"] == "High":
            st.error("High-risk indicators found. Treat the content cautiously.")
        elif report["risk_level"] == "Medium":
            st.warning("Some warning signs were found. Review the evidence.")
        else:
            st.success("Few configured warning signs were found. This does not prove safety.")

        st.subheader("Evidence")
        for finding in report["findings"]:
            st.write(f"• {finding}")

        st.subheader("URLs found")
        if report["urls_found"]:
            for url in report["urls_found"]:
                st.code(url)
        else:
            st.write("No complete HTTP/HTTPS URLs were detected.")

        report["submitted_text"] = user_text
        report["tool_note"] = (
            "Rule-based educational triage only; not a definitive verdict."
        )

        st.download_button(
            "⬇️ Download investigation report (JSON)",
            data=json.dumps(report, indent=2),
            file_name="phishtrace_report.json",
            mime="application/json",
        )

st.divider()
st.caption(
    "Safety note: HTTPS does not guarantee trustworthiness. "
    "Do not enter real passwords, OTPs, or private information."
)

# --- Investigation Dashboard ---
st.divider()
st.header("📊 Investigation Dashboard")

if "investigation_history" not in st.session_state:
    st.session_state.investigation_history = []

st.caption(
    "Dashboard history is stored for this browser session only. "
    "It resets when the session is cleared."
)

if st.session_state.investigation_history:
    history = st.session_state.investigation_history

    total = len(history)
    high = sum(1 for item in history if item["risk_level"] == "High")
    medium = sum(1 for item in history if item["risk_level"] == "Medium")
    low = sum(1 for item in history if item["risk_level"] == "Low")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total analyzed", total)
    c2.metric("High risk", high)
    c3.metric("Medium risk", medium)
    c4.metric("Low risk", low)

    st.subheader("Recent investigations")
    st.dataframe(history, use_container_width=True)

    st.download_button(
        "Download history as CSV",
        data=__import__("pandas").DataFrame(history).to_csv(index=False),
        file_name="phishtrace_history.csv",
        mime="text/csv",
    )
else:
    st.info("No investigations recorded in this session yet.")
