
from core.pcap_loader import load_pcap
from core.dns_extractor import extract_dns
from core.http_extractor import extract_http
from core.ip_extractor import extract_ips
from core.protocol_detector import detect_protocols

from intelligence.aggregator import build_intelligence
from intelligence.risk_engine import analyze_risk
from intelligence.threat_score import calculate_threat_score
from intelligence.enrichment import enrich_intelligence
from intelligence.timeline import build_timeline
from intelligence.ioc_detector import detect_iocs
from intelligence.geo_context import enrich_geo
from intelligence.behavioral_flags import detect_behavior

#  ADVANCED ENGINES
from intelligence.correlation_engine import correlate_behavior
from intelligence.entropy_engine import analyze_domain_entropy
from intelligence.session_analyzer import build_sessions, analyze_sessions
from intelligence.ndr_engine import calculate_ndr_signals  

from report.formatter import generate_report
from report.exporter import export_json
from report.analyst_summary import build_summary


def main():
    print("\n[+] Passive Threat Intelligence Engine Starting...\n")

    pcap_path = "sample_data/test_capture.pcap"

    packets = load_pcap(pcap_path)

    dns_data = extract_dns(packets)
    http_data = extract_http(packets)
    ip_data = extract_ips(packets)
    protocols = detect_protocols(packets)

    intel = build_intelligence(
        dns_data,
        http_data,
        ip_data,
        protocols
    )

    timeline = build_timeline(packets)

    risk_output = analyze_risk(intel)
    risks = risk_output["risks"]
    mitre_hints = risk_output["mitre"]

    threat_score = calculate_threat_score(intel)
    enrichment = enrich_intelligence(intel)

    behavior_flags = detect_behavior(intel)
    correlation_findings = correlate_behavior(intel)

    ioc_hits = detect_iocs(intel)
    entropy_findings = analyze_domain_entropy(intel)

    sessions = build_sessions(packets)
    session_findings = analyze_sessions(sessions)

    #  NDR BEHAVIOR SIGNALS 
    ndr_signals = calculate_ndr_signals(intel, sessions)

    geo_context = enrich_geo(intel)
    analyst_summary = build_summary(threat_score)

    report = generate_report(
        intel,
        risks,
        threat_score,
        mitre_hints,
        enrichment,
        timeline,
        behavior_flags + correlation_findings + session_findings,
        ioc_hits + entropy_findings,
        geo_context,
        analyst_summary,
        ndr_signals   
    )

    print(report)

    export_json(intel, risks, threat_score)


if __name__ == "__main__":
    main()