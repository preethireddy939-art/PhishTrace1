# PhishTrace — Beginner Cybersecurity Project

## Project summary
PhishTrace is a Python + Streamlit educational prototype that checks a URL or email text for configured phishing warning signs. It explains which rules were triggered and exports a JSON report.

## Features
- URL or email-text input
- Transparent rule-based scoring (0–100)
- Low / Medium / High category
- Explanations for findings
- JSON report download
- Built-in sample inputs
- No network requests to submitted URLs

## Requirements
- Python 3.10–3.14
- Internet connection for installing Streamlit
- VS Code or another text editor (optional)

## Setup on Windows
1. Install Python from https://www.python.org/downloads/ and enable the option to add Python to PATH if the installer offers it.
2. Open Command Prompt in this folder.
3. Create a virtual environment:
   `python -m venv .venv`
4. Activate it:
   `.venv\Scripts\activate`
5. Install dependencies:
   `python -m pip install -r requirements.txt`
6. Run:
   `python -m streamlit run app.py`
7. Open the local address shown in the terminal (usually http://localhost:8501).

If `python` is not recognized, try `py` instead of `python`.

## Test checklist
1. Empty input -> app asks for input.
2. `http://account-verify.example.com/login` -> HTTP and keyword warnings should appear.
3. `https://www.example.com/` -> HTTPS note should appear; HTTPS must not be described as proof of safety.
4. Email text `URGENT! Your account is suspended. Click here to verify your password.` -> several suspicious phrase warnings.
5. Download report -> JSON file should contain input, score, level, findings, timestamp, and disclaimer.

## Limitations
- The score is a heuristic, not a probability or confirmed verdict.
- It may produce false positives and false negatives.
- No live reputation lookup, machine learning, attachment analysis, or email-header verification is implemented.
- Never paste real passwords, confidential emails, or personal data into a demo.
- Analyse only information you are authorized to inspect.

## Future enhancements
- Add unit tests for the analysis function.
- Add a local CSV history with user consent.
- Integrate a reputable threat-intelligence API with rate limits and privacy controls.
- Add email-header analysis using safe, user-provided sample files.
- Evaluate a machine-learning classifier against a labelled dataset.

## Interview summary
“I built PhishTrace, a defensive cybersecurity prototype in Python and Streamlit. It analyses URLs or email text for common phishing indicators, explains the rules triggered, and exports a JSON investigation report. It is rule-based rather than a definitive detector, so I clearly document false positives and false negatives.”
