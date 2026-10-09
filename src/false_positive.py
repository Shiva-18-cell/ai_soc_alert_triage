import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.trusted_entities import (
    KNOWN_SERVICE_ACCOUNTS,
    TRUSTED_SOURCE_IPS,
    TRUSTED_HOSTS
)


def analyze_false_positive(incident):

    reasons = []

    username = incident["username"]
    source_ip = incident["source_ip"]
    hostname = incident["hostname"]

    if username in KNOWN_SERVICE_ACCOUNTS:
        reasons.append(
            "Known service account"
        )

    if source_ip in TRUSTED_SOURCE_IPS:
        reasons.append(
            "Trusted source IP"
        )

    if hostname in TRUSTED_HOSTS:
        reasons.append(
            "Trusted hostname"
        )

    if reasons:

        classification = "LIKELY_BENIGN"

    else:

        classification = "REQUIRES_INVESTIGATION"

    return {
        "classification": classification,
        "reasons": reasons
    }