# 🛡️ SIEM Log Anomaly Detector

This script scans SSH auth logs and detects brute-force attacks based on repeated failed login attempts from the same IP.

## 🔍 Features
- Parses standard Linux `auth.log`
- Flags IPs with more than 5 failed attempts
- Simple regex-based detection

## 🧪 Sample Output

[ALERT] Brute-force suspected from IP: 192.168.1.101 - 8 attempts


## 🛠️ How to Use

```bash
python log_parser.py
Edit sample_logs/auth.log with real or test log entries.

