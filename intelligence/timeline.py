def build_timeline(packets):

    first_seen = None
    last_seen = None

    for pkt in packets:
        try:
            ts = pkt.sniff_time
            if not first_seen:
                first_seen = ts
            last_seen = ts
        except:
            continue

    return {
        "first_seen": str(first_seen),
        "last_seen": str(last_seen)
    }