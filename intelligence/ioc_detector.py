SUSPICIOUS_KEYWORDS = ["pastebin", "tor", "temp-mail", "doctorbase"]

def detect_iocs(intel):

    hits = []

    for d in intel["domains"]:
        domain_lower = d.lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in domain_lower:
                hits.append(f"Suspicious domain keyword: {d}")

        # 🔥 Length-based anomaly (non-keyword logic)
        if len(domain_lower) > 40:
            hits.append(f"Unusually long domain detected: {d}")

    return hits