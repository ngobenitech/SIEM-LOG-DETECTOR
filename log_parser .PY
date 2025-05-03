import re

def detect_brute_force(log_path):
    with open(log_path, 'r') as f:
        logs = f.readlines()

    failed_logins = {}

    for line in logs:
        if "Failed password" in line:
            ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                ip = ip.group(1)
                failed_logins[ip] = failed_logins.get(ip, 0) + 1

    for ip, count in failed_logins.items():
        if count > 5:
            print(f"[ALERT] Brute-force suspected from IP: {ip} - {count} attempts")

if __name__ == "__main__":
    detect_brute_force('sample_logs/auth.log')

