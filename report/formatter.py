def generate_report(
    intel,
    risks,
    threat_score,
    mitre_hints,
    enrichment,
    timeline,
    behavior_flags,
    ioc_hits,
    geo_context,
    analyst_summary,
    ndr_signals   # ⭐ NEW PARAMETER
):

    print("[+] Generating intelligence report...\n")

    if threat_score >= 70:
        level = "HIGH RISK"
    elif threat_score >= 40:
        level = "MODERATE RISK"
    else:
        level = "LOW RISK"

    lines = []

    lines.append("\n========== Passive Threat Intelligence Report ==========\n")

    lines.append("[ Analyst Summary ]")
    lines.append(f" {analyst_summary}")
    lines.append(f"\nThreat Score: {threat_score}/100 ({level})\n")

    lines.append("[ Timeline ]")
    lines.append(f" First Seen: {timeline.get('first_seen')}")
    lines.append(f" Last Seen:  {timeline.get('last_seen')}")

    lines.append("\n[ Top Domains ]")
    if enrichment.get("top_domains"):
        for domain, count in enrichment["top_domains"]:
            lines.append(f" - {domain} ({count})")
    else:
        lines.append(" - None")

    lines.append("\n[ Top External IPs ]")
    if enrichment.get("top_ips"):
        for ip, count in enrichment["top_ips"]:
            lines.append(f" - {ip} ({count})")
    else:
        lines.append(" - None")

    lines.append("\n[ Protocols Detected ]")
    for p in intel.get("protocols", []):
        lines.append(f" - {p}")

    lines.append("\n[ Behavioral Indicators ]")
    if behavior_flags:
        for b in behavior_flags:
            lines.append(f" - {b}")
    else:
        lines.append(" - None")

    # ⭐ NEW NDR SIGNAL SECTION
    lines.append("\n[ NDR Behavioral Signal Scores ]")
    if ndr_signals:
        for name, score in ndr_signals.items():
            lines.append(f" - {name}: {round(score, 2)}")
    else:
        lines.append(" - None")

    lines.append("\n[ IOC & Anomaly Detections ]")
    if ioc_hits:
        for i in sorted(set(ioc_hits)):
            lines.append(f" - {i}")
    else:
        lines.append(" - None")

    lines.append("\n[ Geo Context (Simulated) ]")
    if geo_context:
        for g in geo_context:
            lines.append(f" - {g}")
    else:
        lines.append(" - None")

    lines.append("\n[ Risk Observations ]")
    if risks:
        for r in risks:
            lines.append(f" - {r}")
    else:
        lines.append(" - None")

    lines.append("\n[ MITRE ATT&CK Hints ]")
    if mitre_hints:
        for m in mitre_hints:
            lines.append(f" - {m}")
    else:
        lines.append(" - None")

    lines.append("\n========================================================\n")

    return "\n".join(lines)