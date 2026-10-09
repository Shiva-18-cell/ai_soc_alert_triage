
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from parser import load_events
from normalizer import normalize_events
from detector import detect_authentication_attack
from correlator import create_incidents
from false_positive import analyze_false_positive


file_path = PROJECT_ROOT / "data" / "raw" / "windows_authentication.csv"

raw_events = load_events(file_path)
events = normalize_events(raw_events)

detections = detect_authentication_attack(events)
incidents = create_incidents(detections, events)

print("\n=== FALSE POSITIVE ANALYSIS ===\n")

for incident in incidents:
    result = analyze_false_positive(incident)

    print(f"Incident: {incident['incident_id']}")
    print(f"Classification: {result['classification']}")
    print("Reasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"- {reason}")
    else:
        print("- No benign indicators found")

    print()
