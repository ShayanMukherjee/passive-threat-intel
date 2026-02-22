# core/dns_extractor.py

from utils.logger import info


def extract_dns(packets):
    info("Extracting DNS intelligence...")

    domains = set()

    for pkt in packets:
        try:
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                domains.add(pkt.dns.qry_name)
        except:
            continue

    return list(domains)