import re, json

def trigger_alert(message):
    try:
        import winsound
        winsound.MessageBeep(winsound.MB_ICONWARNING)
    except Exception:
        print("\a" + message)

def analyze_log(file_path):
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    suspicious = set()
    brute = {}
    unauthorized = set()

    with open(file_path, "r") as f:
        for line in f:
            ips = re.findall(ip_pattern, line)
            line = line.lower()

            for ip in ips:
                if "failed" in line:
                    brute[ip] = brute.get(ip, 0) + 1

                if "denied" in line or "unauthorized" in line:
                    unauthorized.add(ip)

    for ip, count in brute.items():
        if count > 3:
            suspicious.add(ip)

    alert = bool(suspicious or unauthorized)
    alert_message = (
        f"Alert: {len(suspicious)} suspicious IP(s), "
        f"{sum(brute[ip] for ip in suspicious)} brute-force attempt(s), and "
        f"{len(unauthorized)} unauthorized IP(s) detected."
        if alert else
        "No suspicious IPs or brute-force alerts detected."
    )

    if alert:
        trigger_alert(alert_message)

    result = {
        "suspicious_ips": sorted(suspicious),
        "brute_force": brute,
        "unauthorized": sorted(unauthorized),
        "alert": alert,
        "alert_message": alert_message
    }

    with open("results/log.json", "w") as f:
        json.dump(result, f, indent=4)

    return result
