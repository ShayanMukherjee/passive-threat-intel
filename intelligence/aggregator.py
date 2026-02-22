# intelligence/aggregator.py

def build_intelligence(dns_data, http_data, ip_data, protocols):

    print("[+] Aggregating intelligence...")

    intel = {
        "domains": dns_data,
        "user_agents": http_data,
        "ips": ip_data,
        "protocols": protocols
    }

    return intel