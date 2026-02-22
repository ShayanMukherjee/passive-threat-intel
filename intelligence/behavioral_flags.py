def detect_behavior(intel):

    flags = []

    # DNS burst heuristic
    if len(intel["domains"]) > 20:
        flags.append("High DNS activity pattern")

    # Device diversity heuristic
    if len(intel["user_agents"]) > 5:
        flags.append("Multiple device fingerprints observed")

    # Protocol diversity heuristic ⭐ NEW
    if len(intel["protocols"]) > 8:
        flags.append("High protocol diversity observed")

    return flags