from scapy.all import ICMP, IP, IPv6, Raw, TCP, UDP, rdpcap, sniff
import json
import os


ATTACK_TYPES = {
    "SQL Injection": 0,
    "XSS Attack": 0,
    "Command Injection": 0,
    "Normal": 0
}


def empty_attack_summary():
    return ATTACK_TYPES.copy()


def detect_attack(pkt):
    if not pkt.haslayer(Raw):
        return "Normal"

    payload = pkt[Raw].load.decode(errors="ignore").lower()

    if "select" in payload or "union" in payload or "' or" in payload:
        return "SQL Injection"
    if "<script" in payload or "javascript:" in payload:
        return "XSS Attack"
    if "cmd=" in payload or "powershell" in payload or "/bin/sh" in payload:
        return "Command Injection"

    return "Normal"


def packet_to_result(pkt):
    src = dst = None

    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst

    if pkt.haslayer(TCP):
        protocol = "TCP"
    elif pkt.haslayer(UDP):
        protocol = "UDP"
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "Other"

    if not src or not dst:
        return None

    return {
        "source": src,
        "destination": dst,
        "protocol": protocol,
        "attack": detect_attack(pkt)
    }


def is_between_hosts(pkt, ip1, ip2):
    result = packet_to_result(pkt)
    if not result:
        return False

    src = result["source"]
    dst = result["destination"]
    return (src == ip1 and dst == ip2) or (src == ip2 and dst == ip1)


def save_packet_report(data, filename):
    os.makedirs("results", exist_ok=True)

    with open(os.path.join("results", filename), "w") as f:
        json.dump(data, f, indent=4)


def analyze_live_packets(ip1, ip2, duration=20):
    results = []
    attack_summary = empty_attack_summary()
    error = None

    ip1 = ip1.strip()
    ip2 = ip2.strip()

    def process(pkt):
        result = packet_to_result(pkt)
        if not result:
            return

        src = result["source"]
        dst = result["destination"]

        if (src == ip1 and dst == ip2) or (src == ip2 and dst == ip1):
            results.append(result)
            attack_summary[result["attack"]] += 1

    try:
        sniff(prn=process, timeout=duration, store=False)
    except PermissionError:
        error = "Live monitoring needs administrator permission and Npcap/WinPcap packet capture support."
    except OSError as exc:
        error = f"Live monitoring could not start: {exc}"
    except Exception as exc:
        error = f"Live monitoring failed: {exc}"

    data = {
        "total_packets": len(results),
        "attack_summary": attack_summary,
        "packets": results,
        "mode": "live",
        "monitored_hosts": [ip1, ip2],
        "duration": duration,
        "error": error
    }

    save_packet_report(data, "live_packet.json")
    return data


def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    results = []
    attack_summary = empty_attack_summary()

    for pkt in packets:
        result = packet_to_result(pkt)
        if not result:
            continue

        results.append(result)
        attack_summary[result["attack"]] += 1

    data = {
        "total_packets": len(results),
        "attack_summary": attack_summary,
        "packets": results,
        "mode": "pcap",
        "error": None
    }

    save_packet_report(data, "packet.json")
    return data
