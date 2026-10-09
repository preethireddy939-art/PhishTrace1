# PhishTrace — Project Report

## Title
PhishTrace: Smart Phishing Investigation and Reporting System

## Abstract
PhishTrace is a beginner-friendly defensive cybersecurity application built with Python and Streamlit. It analyses a user-supplied URL or email text for selected warning signs, assigns a transparent heuristic risk score, presents explanations, and allows a JSON report to be downloaded. The application does not visit submitted URLs or claim to confirm malicious activity.

## Problem statement
Phishing messages often use urgency, account warnings, credential requests, and deceptive links to trick users. Beginners may not know which signs to check. PhishTrace demonstrates how simple, explainable checks can support an initial review.

## Objectives
1. Accept a URL or sample email text.
2. Identify configured warning signs.
3. Calculate a rule-based score and category.
4. Explain findings in understandable language.
5. Export findings as a JSON report.
6. demonstrate safe, defensive cybersecurity practice.

## Technologies
- Python: core logic and data processing
- Streamlit: web interface
- Python standard library: URL parsing, IP address checks, regular expressions, JSON and timestamps

## Methodology
1. User selects URL or email-text mode.
2. The input is parsed or converted to lowercase for text checks.
3. Rules check for indicators such as HTTP, IP-address hosts, long URLs, URL shorteners, and suspicious words.
4. Rule weights are added and capped at 100.
5. The score is grouped as Low (0–29), Medium (30–59), or High (60–100).
6. Findings are shown and exported to JSON.

## System requirements
- Python 3.10 or newer, within Streamlit's supported versions
- Streamlit Python package
- Windows, macOS, or Linux
- Browser for the local interface

## Testing
Use the test checklist in README.md. Record actual observed results after running the application; do not claim testing was successful until you have run it on your device.

## Limitations
This prototype is not a production anti-phishing product. Its score is not a probability. HTTPS does not guarantee trustworthiness. Benign messages may trigger rules, and sophisticated phishing may evade them. No external reputation database or machine-learning model is used.

## Future scope
- Unit tests and a labelled evaluation dataset
- Optional threat-intelligence integration
- Email header analysis
- Improved URL/domain parsing and allow-listed tests
- Privacy-conscious case history and PDF export

## Conclusion
PhishTrace demonstrates basic defensive security analysis, Python programming, web-interface development, transparent rule-based scoring, and structured reporting. It is suitable as a learning prototype and can be extended through careful testing and documented evaluation.
