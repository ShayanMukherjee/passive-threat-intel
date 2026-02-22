# intelligence/session_analyzer.py

from collections import defaultdict


def build_sessions(packets):

    sessions = defaultdict(list)

    for pkt in packets:
        try:
            if hasattr(pkt, "ip"):
                key = f"{pkt.ip.src}->{pkt.ip.dst}"
                sessions[key].append(pkt.highest_layer)
        except:
            continue

    return sessions


def analyze_sessions(sessions):

    findings = []

    for session, layers in sessions.items():

        unique_protocols = set(layers)

        # session complexity heuristic
        if len(unique_protocols) > 6:
            findings.append(f"High protocol diversity in session {session}")

    return findings