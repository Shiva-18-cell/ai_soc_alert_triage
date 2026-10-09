
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from parser import load_events
from normalizer import normalize_events
from detector import detect_authentication_attack
from correlator import create_incidents
from false_positive import analyze_false_positive
from risk_engine import calculate_risk


def run_pipeline():
    file_path = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / "windows_authentication.csv"
    )

    # 1. Load events
    raw_events = load_events(file_path)

    # 2. Normalize events
    events = normalize_events(raw_events)

    # 3. Detect suspicious patterns
    detections = detect_authentication_attack(events)

    # 4. Correlate events into incidents
    incidents = create_incidents(detections, events)

    # 5. Analyze and score each incident
    results = []

    for incident in incidents:
        fp_result = analyze_false_positive(incident)
        risk_result = calculate_risk(incident)

        results.append({
            **incident,
            "false_positive_analysis": fp_result,
            "risk": risk_result
        })

    # 6. Display final report
    print("\n=== SOC TRIAGE REPORT ===")
    print(f"Total events: {len(events)}")
    print(f"Detections: {len(detections)}")
    print(f"Incidents: {len(results)}")

    for incident in results:
        print("\n" + "=" * 45)
        print(f"Incident: {incident['incident_id']}")
        print(f"Rule: {incident['rule_id']}")
        print(f"User: {incident['username']}")
        print(f"Source IP: {incident['source_ip']}")
        print(f"Host: {incident['hostname']}")
        print(f"Failed logins: {incident['failed_attempts']}")

        fp = incident["false_positive_analysis"]
        risk = incident["risk"]

        print(f"Classification: {fp['classification']}")
        print(f"Risk score: {risk['risk_score']}/100")
        print(f"Risk severity: {risk['risk_severity']}")

        print("\nRisk reasons:")
        for reason in risk["risk_reasons"]:
            print(f"- {reason}")

    # 7. Save report as JSON
    report_path = PROJECT_ROOT / "data" / "processed" / "triage_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(results, report_file, indent=2, default=str)

    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    run_pipeline()
