
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from risk_engine import calculate_risk


incident = {
    "incident_id": "INC-0001",
    "username": "administrator",
    "source_ip": "192.168.100.25",
    "failed_attempts": 4,
    "successful_login": True
}

result = calculate_risk(incident)

print("\n=== RISK SCORING TEST ===\n")
print(f"Incident: {incident['incident_id']}")
print(f"Risk Score: {result['risk_score']}/100")
print(f"Severity: {result['risk_severity']}")

print("\nReasons:")
for reason in result["risk_reasons"]:
    print(f"- {reason}")
