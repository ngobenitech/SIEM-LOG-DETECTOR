import re

def parse_log(file_path):
    failed_logins = []
    pattern = r"Failed password for.*from (\d+\.\d+\.\d+\.\d+)"

    with open(file_path, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                failed_logins.append(ip)

    ip_count = {}
    for ip in failed_logins:
        ip_count[ip] = ip_count.get(ip, 0) + 1

    for ip, count in ip_count.items():
        if count >= 2:
            print(f"[!] Suspicious activity detected from IP: {ip} ({count} failed attempts)")

if __name__ == "__main__":
    parse_log("sample_logs/auth.log")
