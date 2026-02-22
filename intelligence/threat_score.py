# intelligence/threat_score.py

from config.settings import INSECURE_PROTOCOLS, MAX_EXTERNAL_IPS_BEFORE_WARNING, SUSPICIOUS_USER_AGENTS


def calculate_threat_score(intel):
    """
    Generates a threat score from 0–100 based on passive intelligence.
    """

    score = 0

    # Insecure protocol weight
    for proto in intel["protocols"]:
        if proto.upper() in INSECURE_PROTOCOLS:
            score += 20

    # Many external IPs
    if len(intel["ips"]) > MAX_EXTERNAL_IPS_BEFORE_WARNING:
        score += 20

    # Suspicious user agents
    for ua in intel["user_agents"]:
        for keyword in SUSPICIOUS_USER_AGENTS:
            if keyword in ua.lower():
                score += 10

    # Clamp value between 0 and 100
    score = min(score, 100)

    return score