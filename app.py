import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

import streamlit as st

st.set_page_config(page_title="PhishTrace | Security Lab", page_icon="ðŸ›¡ï¸", layout="wide")

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly"}
TERMS = ["verify", "login", "password", "urgent", "suspended", "account", "free prize", "claim now", "bank details", "confirm identity", "one-time password", "otp", "gift card", "payment failed", "act now", "security alert", "unusual activity"]

def analyze_text(text):
    findings, score = [], 0
    cleaned = unquote(text.strip())
    lowered = cleaned.lower()
    urls = re.findall(r'https?://[^\s<>"\']+', cleaned, flags=re.IGNORECASE)

    for raw in urls:
        url = raw.rstrip(".,;!?)\"]}")
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
                findings.append(f"URL uses an IP address instead of a named domain: {host}")
                score += 20
            except ValueError:
                pass
            if host in SHORTENERS:
                findings.append(f"URL uses a known shortening service: {host}")
                score += 15
            if "xn--" in host:
                findings.append("Domain contains punycode, which can be used in look-alike domains.")
                score += 15
            if host.count(".") >= 4:
                findings.append("Domain has an unusually deep subdomain structure.")
                score += 10
            if "@" in parsed.netloc:
                findings.append("URL contains an @ symbol in its authority section.")
                score += 20
            if parsed.scheme.lower() != "https":
                findings.append("URL does not use HTTPS; this alone does not prove it is malicious.")
                score += 5
            if len(url) > 100:
                findings.append("URL is unusually long.")
                score += 10
            if re.search(r"%[0-9a-fA-F]{2}", url):
                findings.append("URL contains percent-encoded characters.")
                score += 5
            if re.search(r"(login|verify|secure|account|password|wallet|payment)", host):
                findings.append("Domain name contains a term often used in account or payment lures.")
                score += 8
            if parsed.username or parsed.password:
                findings.append("URL includes user-info before the hostname, which can be misleading.")
                score += 20
        except (ValueError, UnicodeError):
            findings.append("A URL could not be parsed reliably.")
            score += 5

    for term in TERMS:
        if term in lowered:
            findings.append(f"Potential social-engineering wording detected: '{term}'.")
            score += 6
    if re.search(r"\b(password|passcode|otp|one-time password|bank details)\b", lowered):
        findings.append("Message appears to request or mention sensitive credentials or financial information.")
        score += 10

    findings = list(dict.fromkeys(findings))
    score = min(score, 100)
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    if not urls:
        findings.append("No complete HTTP/HTTPS URL was detected in the submitted text.")
    if not findings:
        findings.append("No configured warning signs were detected. This does not prove the content is safe.")
    return {"risk_score": score, "risk_level": level, "findings": findings, "urls_found": urls}

if "investigation_history" not in st.session_state:
    st.session_state["investigation_history"] = []
if "latest_report" not in st.session_state:
    st.session_state["latest_report"] = None

st.title("ðŸ›¡ï¸ PhishTrace")
st.subheader("Smart Phishing Investigation & Reporting System")
st.caption("Educational security analysis â€¢ Rule-based detection")
st.warning("PhishTrace does not visit submitted URLs. Scores are heuristic, not probabilities or definitive verdicts. Never enter real passwords, OTPs, or private information.")

with st.expander("How to use PhishTrace"):
    st.write("Paste a suspicious URL or email/message, then tap Analyze. Review the findings rather than relying only on the score. HTTPS does not guarantee safety.")

sample = "URGENT: Verify your password immediately at http://192.0.2.10/account-login to avoid account suspension."
user_text = st.text_area("Suspicious URL or email/message text", height=170, placeholder="Paste text here. Use fictional examples for testing.")
a, b, c = st.columns(3)
with a:
    analyze_clicked = st.button("ðŸ”Ž Analyze", type="primary", use_container_width=True)
with b:
    sample_clicked = st.button("Load sample", use_container_width=True)
with c:
    clear_clicked = st.button("Clear history", use_container_width=True)

if sample_clicked:
    st.info("Copy this fictional sample into the text box, then tap Analyze.")
    st.code(sample)
if clear_clicked:
    st.session_state["investigation_history"] = []
    st.session_state["latest_report"] = None
    st.success("Session history cleared.")

if analyze_clicked:
    if not user_text.strip():
        st.warning("Please enter a URL or message before analyzing.")
    else:
        result = analyze_text(user_text)
        report = {
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "urls_found": result["urls_found"],
            "findings": result["findings"],
            "findings_count": len(result["findings"]),
            "submitted_text": user_text,
            "tool_note": "Rule-based educational triage only; not a definitive verdict."
        }
        st.session_state["latest_report"] = report
        st.session_state["investigation_history"].append({
            "timestamp_utc": report["timestamp_utc"],
            "risk_score": report["risk_score"],
            "risk_level": report["risk_level"],
            "urls_found": ", ".join(report["urls_found"]),
            "findings_count": report["findings_count"],
            "text_preview": re.sub(r"\s+", " ", user_text)[:100]
        })

if st.session_state["latest_report"]:
    report = st.session_state["latest_report"]
    st.divider()
    st.header("ðŸ” Investigation Results")
    x, y, z = st.columns(3)
    x.metric("Risk score", f'{report["risk_score"]}/100')
    y.metric("Risk level", report["risk_level"])
    z.metric("Warning signs", report["findings_count"])
    if report["risk_level"] == "High":
        st.error("High-risk indicators found. Verify through a trusted channel.")
    elif report["risk_level"] == "Medium":
        st.warning("Some warning signs were found. Review the evidence carefully.")
    else:
        st.info("Few configured warning signs were found. This does not mean the content is safe.")
    st.subheader("Evidence found")
    for finding in report["findings"]:
        st.write("â€¢ " + finding)
    st.subheader("URLs detected")
    if report["urls_found"]:
        for url in report["urls_found"]:
            st.code(url)
    else:
        st.write("No complete HTTP/HTTPS URLs detected.")
    st.download_button("â¬‡ï¸ Download investigation report (JSON)", data=json.dumps(report, indent=2, ensure_ascii=False), file_name="phishtrace_report.json", mime="application/json")

st.divider()
st.header("ðŸ“Š Investigation Dashboard")
history = st.session_state["investigation_history"]
if history:
    total = len(history)
    high = sum(row["risk_level"] == "High" for row in history)
    medium = sum(row["risk_level"] == "Medium" for row in history)
    low = sum(row["risk_level"] == "Low" for row in history)
    x, y, z, w = st.columns(4)
    x.metric("Total analyzed", total)
    y.metric("High risk", high)
    z.metric("Medium risk", medium)
    w.metric("Low risk", low)
    st.subheader("Recent investigations")
    st.dataframe(history[::-1], use_container_width=True, hide_index=True)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(history[0].keys()))
    writer.writeheader()
    writer.writerows(history)
    st.download_button("â¬‡ï¸ Download history (CSV)", data=buffer.getvalue(), file_name="phishtrace_history.csv", mime="text/csv")
else:
    st.info("No investigations recorded in this browser session yet. Analyze a message to populate the dashboard.")

st.caption("Prototype limitation: rule-based checks can miss attacks or flag legitimate content. History is temporary and may reset when the app session ends.")
