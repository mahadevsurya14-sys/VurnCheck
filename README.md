# VurnCheck

**Web Vulnerability Assessment Tool**  
**Author:** Mahadu Suryavanshi  
**Version:** 1.0.0  
**Platform:** Kali Linux / Linux  
**Language:** Python 3

VurnCheck is a lightweight, modular scanner for authorized web application security assessment. It focuses on safe detection and reporting rather than destructive exploitation.

## Features
- Same-origin bounded crawling
- GET/POST form and parameter discovery
- SQL Injection indicators using non-destructive probes
- Reflected and limited stored-XSS indicators using a harmless canary
- Static DOM-XSS source/sink indicators
- Security-header checks
- Basic information-disclosure checks
- Severity and confidence values
- JSON and HTML reports
- Rate limiting, timeout, request limits and response-size limits
- Structured logging and unit tests

## Safety
Use VurnCheck only on applications you own or have explicit permission to test. The tool does not dump databases, steal credentials/cookies/tokens, run commands, modify/delete data, brute-force accounts or perform DoS testing. External domains are out of scope by default.

## Installation on Kali Linux
```bash
python3 --version
sudo apt update
sudo apt install -y python3-venv
cd VurnCheck
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python3 main.py --help
python3 main.py -u http://127.0.0.1:3000 --scan all --json --html
python3 main.py -u http://127.0.0.1:3000 --scan sqli
python3 main.py -u http://127.0.0.1:3000 --scan xss
python3 main.py -u http://127.0.0.1:3000 --scan headers
```

Useful options:
`-d/--depth`, `--max-requests`, `--delay`, `--timeout`, `--user-agent`, `--scan`, `--output`, `--json`, `--html`, `--verbose`.

## OWASP Juice Shop
Run Juice Shop locally, for example on `http://127.0.0.1:3000`, and scan only that local instance:
```bash
python3 main.py -u http://127.0.0.1:3000 --scan all --json --html --depth 2 --max-requests 100
```

## Reports
JSON is machine-readable. HTML is a human-readable assessment report. Sensitive values are masked or omitted where appropriate.

## Tests
```bash
python3 -m unittest discover -s tests -v
```

## Limitations
VurnCheck 1.0.0 provides indicator-based detection. Findings, especially DOM-XSS and SQLi response-difference indicators, require manual validation. It is not a replacement for a full professional penetration test.

## Project Structure
```text
VurnCheck/
├── main.py
├── config.py
├── requirements.txt
├── README.md
├── LICENSE
├── core/
├── scanners/
├── detection/
├── reports/
├── utils/
└── tests/
```

## Author
Mahadu Suryavanshi
