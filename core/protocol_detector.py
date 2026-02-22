def detect_protocols(packets):
    print("[+] Detecting protocols...")

    protocols = set()

    for pkt in packets:
        try:
            protocols.add(pkt.highest_layer)
        except:
            continue

    return list(protocols)