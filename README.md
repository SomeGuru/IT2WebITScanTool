# IT2Innovations Web IT Scan Tool

![Version](https://img.shields.io/badge/version-1.0.1-blue)
![License](https://img.shields.io/badge/license-MIT%20%26%20Apache-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

## Creator: Mike Larios
## Engineering Validation: Mike Larios
## License: MIT & Apache

## WARNING: LEGAL NOTICE

**This program is a testing tool, Pen Testing tool, and a tool used to exploit vulnerabilities of weakened or compromised websites.**

This can get you in trouble if you are not authorized by the site/ISP/Owner of the domain you are testing against. All legal ramifications will be on you, not any companies, persons, or devices mentioned in this file. We hold no legal or other responsible parts to the usage of this application.

**This is created and considered "AS-IS" best effort coded.**

---

## Features

- SSL/TLS Configuration Check
- Security Headers Analysis
- CORS Configuration Check
- Information Disclosure Detection
- Clickjacking Protection Check
- XSS Protection Analysis
- Cookie Security Check
- Server Information Disclosure
- Directory Listing Check
- Form Security Analysis
- Outdated Components Detection
- CSRF Protection Check
- SQL Injection Indicators

## Installation

### Download Executable
1. Go to [Releases](https://github.com/someguru/IT2WebITScanTool/releases/latest)
2. Download `IT2WebITScanTool.exe`
3. Run the executable

### From Source
```bash
git clone https://github.com/someguru/IT2WebITScanTool.git
cd IT2WebITScanTool
pip install -r requirements.txt
python IT2WebITScanTool.py
```

## Usage

1. Enter the target URL (with or without https://)
2. Click "Start Scan"
3. Confirm you have authorization to scan
4. Review vulnerabilities in the results panel
5. Filter by severity level
6. Export results to JSON

## Building from Source

```bash
pip install pyinstaller pillow
python -c "import urllib.request; urllib.request.urlretrieve('http://www.it2innovations.com/images/favicon.ico', 'it2_icon.ico')"
pyinstaller --onefile --windowed --icon=it2_icon.ico --name=IT2WebITScanTool IT2WebITScanTool.py
```

## Updates

The tool automatically checks for updates on startup. You can also manually check from **Tools > Check for Updates**.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any website.