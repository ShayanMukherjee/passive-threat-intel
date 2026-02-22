# Passive Threat Intelligence Engine

## Overview
Passive Threat Intelligence Engine is a Python-based OSINT analysis tool that converts network packet captures (PCAP files) into actionable reconnaissance intelligence.

Instead of manually inspecting traffic in Wireshark, the tool extracts domains, IPs, device fingerprints, and insecure protocol usage to simulate threat intelligence workflows used during incident response.

---

## Problem Statement
Security analysts often rely on manual packet inspection which can be time-consuming. This project demonstrates how passive network data can be transformed into structured OSINT insights automatically.

---

## Features
- DNS intelligence extraction
- External IP discovery
- HTTP User-Agent fingerprinting
- Insecure protocol detection
- Automated risk observations
- Structured intelligence report

---

## Architecture
PCAP File  
→ Packet Loader  
→ Intelligence Extractors  
→ Aggregation Layer  
→ Risk Engine  
→ Threat Intelligence Report

---

## Example Use Case
- Reconnaissance analysis
- Blue team investigation
- Threat hunting
- Passive asset discovery

---

## Tech Stack
Python  
Pyshark (Wireshark backend)

---

## Future Improvements
- IP reputation lookup
- GeoIP enrichment
- Suspicious domain scoring
- Export reports to JSON/HTML

---

## Disclaimer
This project is for educational and defensive cybersecurity purposes only.