# PhishTrace — Smart Phishing Investigation & Reporting System

Educational Streamlit app using local rule-based indicators to analyze suspicious URL/email text, display a heuristic risk score and findings, and export JSON/CSV reports.

## Run
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Limitations
- Does not visit submitted URLs.
- Score is heuristic, not a probability or definitive verdict.
- HTTPS does not guarantee trustworthiness.
- History is temporary session data, not a permanent database.
- Use fictional examples; never enter real passwords, OTPs, or private information.
