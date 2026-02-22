def build_summary(threat_score):

    if threat_score >= 70:
        return "Potentially malicious activity observed."
    elif threat_score >= 40:
        return "Suspicious patterns detected."
    else:
        return "Normal passive traffic profile."