# DecodeLabs Project 3 — Phishing Awareness Analysis

> **Made by M Luqman Shoaib. Project 3 Decode Labs.**

A modern, explainable phishing-awareness analysis web application built with **Python, Flask, HTML, CSS and JavaScript**.

## Features

- Phishing message analysis
- 0–100 risk scoring
- LOW / MEDIUM / HIGH classification
- Suspicious keyword detection
- Urgency and pressure detection
- Credential, OTP and password request detection
- Financial/payment request detection
- Threat/consequence detection
- Reward/prize bait detection
- Attachment/download lure detection
- Secrecy instruction detection
- Call-to-action detection
- URL extraction and inspection
- URL shortener detection
- Punycode detection
- IP-address URL detection
- HTTP vs HTTPS inspection
- Long URL detection
- Deep-subdomain detection
- Selected unusual-TLD detection
- Red Flag Checklist
- Defensive recommendations
- Training sample
- Local browser history
- JSON history export
- Base64, ROT13 and HTML-entity utilities
- Responsive frontend
- Automated tests
- No remote URL visiting during analysis

## Technology

- Python 3.10+
- Flask
- HTML5
- CSS3
- Vanilla JavaScript
- pytest

## Project Structure

```text
DecodeLabs_Project_3/
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
├── PROJECT_INFO.md
├── LICENSE
├── .gitignore
├── templates/
│   └── index.html
├── static/
│   ├── app.js
│   └── styles.css
└── tests/
    └── test_analyzer.py
```

## How to Run on Windows

### 1. Install Python

Install Python 3.10 or newer.

Verify:

```powershell
python --version
```

If `python` is unavailable, try:

```powershell
py --version
```

### 2. Open the Project

Extract the project and open the folder in VS Code.

Open:

**Terminal → New Terminal**

Make sure the terminal is inside the project folder.

### 3. Create a Virtual Environment

```powershell
python -m venv .venv
```

### 4. Activate It

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Command Prompt:

```cmd
.venv\Scripts\activate
```

You should see `(.venv)` in the terminal.

### 5. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 6. Start the Application

```powershell
python app.py
```

You should see:

```text
Running on http://127.0.0.1:5000
```

### 7. Open the Website

Go to:

```text
http://127.0.0.1:5000
```

Keep the terminal running while using the application.

Stop the server with:

```text
Ctrl + C
```

## If PowerShell Blocks Activation

You can run without activating the environment:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

## Running Tests

```powershell
pytest -q
```

The tests cover high-risk phishing detection, URL-shortener detection and normal-message classification.

## Testing the App

Paste this sample:

```text
URGENT!

Your account will be suspended within 2 hours.

Please verify your password and security code immediately by clicking:
http://bit.ly/verify-account

Failure to do so will result in permanent account termination.
```

Then click **Analyze Message**.

The application should identify multiple phishing indicators and assign a high risk score.

## GitHub Upload

After creating an empty GitHub repository, run:

```powershell
git init
git add .
git commit -m "Complete DecodeLabs Project 3"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/DecodeLabs_Project_3.git
git push -u origin main
```

Do not commit `.venv`, secrets or environment files. The included `.gitignore` already excludes common local files.

### Suggested Repository Description

```text
DecodeLabs Project 3: an explainable phishing-awareness analyzer with red-flag detection, URL intelligence, risk scoring, training scenarios and security utilities.
```

### Suggested Topics

```text
cybersecurity
phishing-detection
security-awareness
python
flask
threat-analysis
information-security
cyber-security
soc
decodelabs
```

## How the Risk Score Works

The analyzer uses transparent heuristics rather than claiming perfect detection.

Indicators such as urgency, credential requests, financial requests, threats and suspicious URLs contribute points.

| Score | Risk |
|---:|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–100 | HIGH |

A result is an analytical aid, not proof that a message is malicious or safe.

## Privacy and Safety

The analyzer:

- Does not visit submitted URLs
- Does not download remote websites
- Does not require API keys
- Does not require a database
- Does not send submitted messages to third-party services
- Stores history locally in the browser

## Limitations

This is an educational cybersecurity-awareness project. Sophisticated phishing campaigns can evade heuristic detection. A low score does not prove safety, and a high score does not mathematically prove malicious intent.

For real-world security operations, combine this type of analysis with professional email security, threat intelligence, sandboxing, authentication controls and incident-response procedures.

## Learning Outcomes

This project demonstrates:

- Python
- Flask
- JavaScript
- HTML/CSS
- Regular expressions
- URL parsing
- Security heuristics
- Phishing awareness
- Explainable analysis
- Defensive security
- Automated testing
- Git/GitHub
- Technical documentation
- Responsive UI design

## Future Improvements

Possible extensions include machine-learning classification, NLP, domain reputation APIs, DNS/WHOIS analysis, threat-intelligence integration, screenshot analysis, attachment analysis, browser extensions, SIEM integration and SOC workflows.

## Author

**M Luqman Shoaib**

**Made by M Luqman Shoaib. Project 3 Decode Labs.**
