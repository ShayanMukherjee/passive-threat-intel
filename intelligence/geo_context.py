def enrich_geo(intel):

    # Simulated enrichment — no API needed
    geo_summary = []

    for ip in intel["ips"][:5]:
        geo_summary.append(f"{ip} → External Region")

    return geo_summary