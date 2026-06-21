import socket
import json
import os

def trigger_alert(message):
    try:
        import winsound
        winsound.MessageBeep(winsound.MB_ICONWARNING)
    except Exception:
        print("\a" + message)

def scan_ports(ip):
    open_ports = []

    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67 : "DHCP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389:"RDP",
        3306:"MYSQL",
        8000: "HTTP-Alt"
    }

    for port in range(20, 600):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)

            if s.connect_ex((ip, port)) == 0:
                service = common_ports.get(port, "Unknown")

                open_ports.append({
                    "port": port,
                    "service": service
                })

            s.close()
        except:
            pass

    
    os.makedirs("results", exist_ok=True)

    alert = bool(open_ports)
    alert_message = (
        f"Alert: {len(open_ports)} open port(s) detected on {ip}."
        if alert else
        "No open ports detected."
    )

    if alert:
        trigger_alert(alert_message)

    data = {
        "target_ip": ip,
        "open_ports": open_ports,
        "alert": alert,
        "alert_message": alert_message
    }

    with open("results/recon.json", "w") as f:
        json.dump(data, f, indent=4)

    return data
