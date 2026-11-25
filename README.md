# VulnFeed - CVE Tracker

**Student:** M. Faizan | **Institute:** PNY Trainings

VulnFeed is a desktop CVE monitoring tool that fetches live vulnerabilities from the NVD API, tracks new & modified CVEs, and generates reports.

## Features
- Live fetch from NVD API 2.0 (Keyword / CVE ID / Date Range)
- CVE Details: Score, Severity, Description, CWE, References
- SQLite Database - No duplicate CVE saved twice
- Detects MODIFIED CVEs (score / description changed)
- Watchlist alerts for keywords like log4j, windows, openssl
- Save Report (.txt), Export CSV / JSON
- 7 / 30 Days Trend Graph

## How to Run
pip install requests matplotlib
python VulnFeed_GUI.py

## How to Build EXE
pyinstaller --onefile --windowed --name VulnFeed VulnFeed_GUI.py
