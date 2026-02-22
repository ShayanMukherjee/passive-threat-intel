# intelligence/risk_engine.py

from config.settings import (
    INSECURE_PROTOCOLS,
    MAX_EXTERNAL_IPS_BEFORE_WARNING,
    SUSPICIOUS_USER_AGENTS
)


def analyze_risk(intel):

    from utils.logger import info
    info("Running risk analysis...")

    risks = []
    mitre_hints = []

    # Insecure protocol detection
    for proto in intel["protocols"]:
        if proto.upper() in INSECURE_PROTOCOLS:
            risks.append(f"Insecure protocol detected: {proto}")
            mitre_hints.append("T1046 - Network Service Discovery")

    # External IP anomaly
    if len(intel["ips"]) > MAX_EXTERNAL_IPS_BEFORE_WARNING:
        risks.append("High number of external connections observed")
        mitre_hints.append("T1595 - Active Scanning")

    # Suspicious automation user-agents
    for ua in intel["user_agents"]:
        for keyword in SUSPICIOUS_USER_AGENTS:
            if keyword in ua.lower():
                risks.append("Possible automated traffic detected")
                mitre_hints.append("T1071 - Application Layer Protocol")

    if not risks:
        risks.append("No major risks detected from passive analysis")

    return {
        "risks": risks,
        "mitre": list(set(mitre_hints))
    }