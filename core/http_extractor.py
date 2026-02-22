# core/http_extractor.py

from utils.logger import info


def extract_http(packets):
    info("Extracting HTTP user-agents...")

    user_agents = set()

    for pkt in packets:
        try:
            if hasattr(pkt, "http") and hasattr(pkt.http, "user_agent"):
                user_agents.add(pkt.http.user_agent)
        except:
            continue

    return list(user_agents)