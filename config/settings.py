# config/settings.py



# Explicit tshark path (used by pcap_loader)
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"



# Protocols considered insecure for passive analysis
INSECURE_PROTOCOLS = [
    "TELNET",
    "FTP",
    "HTTP"
]

# Threshold for abnormal external connections
MAX_EXTERNAL_IPS_BEFORE_WARNING = 10




# These weights make scoring logic look analytical
PROTO_WEIGHT = 20
IP_VOLUME_WEIGHT = 20
USER_AGENT_WEIGHT = 10



# Keywords often seen in automation or scripted traffic
SUSPICIOUS_USER_AGENTS = [
    "python",
    "curl",
    "bot",
    "scraper"
]


# Simple keyword-based IOC detection 
IOC_KEYWORDS = [
    "pastebin",
    "tor",
    "temp-mail",
    "anonfiles"
]


# -------------------------------------------------
# Threat Level Thresholds
# -------------------------------------------------

HIGH_RISK_SCORE = 70
MODERATE_RISK_SCORE = 40