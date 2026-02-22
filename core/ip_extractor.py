# core/ip_extractor.py

from utils.logger import info


def extract_ips(packets):
    info("Extracting external IPs...")

    ips = set()

    for pkt in packets:
        try:
            if hasattr(pkt, "ip"):
                ips.add(pkt.ip.dst)
        except:
            continue

    return list(ips)