# intelligence/enrichment.py

from collections import Counter


def enrich_intelligence(intel):
    from utils.logger import info
    info(" Enriching intelligence...")

    enrichment = {}

    enrichment["top_ips"] = Counter(intel["ips"]).most_common(5)
    enrichment["top_domains"] = Counter(intel["domains"]).most_common(5)

    return enrichment