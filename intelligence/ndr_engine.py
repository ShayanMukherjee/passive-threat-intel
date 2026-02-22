

def calculate_ndr_signals(intel, sessions):

    signals = {}

    # DNS intensity score
    dns_count = len(intel["domains"])
    signals["dns_activity_score"] = min(dns_count / 60, 1.0)

    # Protocol diversity score
    proto_count = len(intel["protocols"])
    signals["protocol_diversity_score"] = min(proto_count / 12, 1.0)

    # External IP spread
    ip_count = len(intel["ips"])
    signals["external_spread_score"] = min(ip_count / 30, 1.0)

    # Session complexity
    complex_sessions = 0
    for s in sessions.values():
        if len(set(s)) > 6:
            complex_sessions += 1

    signals["session_complexity_score"] = min(complex_sessions / 5, 1.0)

    return signals