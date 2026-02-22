
def correlate_behavior(intel):

    findings = []

    has_http = "HTTP" in [p.upper() for p in intel["protocols"]]
    high_dns = len(intel["domains"]) > 10
    many_ips = len(intel["ips"]) > 8

    # Composite behavioral signal
    if has_http and high_dns and many_ips:
        findings.append("Composite behavior: Possible beaconing-like activity")

    if high_dns and not has_http:
        findings.append("DNS-heavy communication pattern")

    return findings