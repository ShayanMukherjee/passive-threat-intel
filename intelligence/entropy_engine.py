# intelligence/entropy_engine.py

import math
from collections import Counter


def shannon_entropy(data):

    if not data:
        return 0

    counts = Counter(data)
    length = len(data)

    return -sum((count/length) * math.log2(count/length) for count in counts.values())


def analyze_domain_entropy(intel):

    suspicious = []

    for domain in intel["domains"]:
        entropy = shannon_entropy(domain)

        # random-looking domains tend to have higher entropy
        if entropy > 4.0 and len(domain) > 18:
            suspicious.append(f"High entropy domain detected: {domain}")

    return suspicious