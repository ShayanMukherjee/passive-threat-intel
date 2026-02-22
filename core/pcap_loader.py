# core/pcap_loader.py

import pyshark
from utils.logger import info, error

# Explicit tshark path (since PATH variable isn't working)
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


def load_pcap(pcap_path):
    """
    Load PCAP using pyshark with explicit tshark path.
    Returns capture object.
    """

    info(f"Loading PCAP: {pcap_path}")

    try:
        capture = pyshark.FileCapture(
            pcap_path,
            tshark_path=TSHARK_PATH,
            keep_packets=True  # Important so multiple extractors can read
        )

        return capture

    except Exception as e:
        error(f"Error loading PCAP: {e}")
        return []