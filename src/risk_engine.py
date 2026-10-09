
def calculate_risk(incident):
    """
    Calculate an explainable risk score from incident evidence.
    This is a prototype scoring model, not a calibrated probability.
    """

    score = 0
    reasons = []

    failed_attempts = incident.get("failed_attempts", 0)
    username = incident.get("username", "").lower()
    source_ip = incident.get("source_ip", "")

    # Multiple authentication failures
    if failed_attempts >= 3:
        score += 25
        reasons.append("Multiple failed login attempts (+25)")

    # Successful login following failures
    if incident.get("successful_login", False):
        score += 25
        reasons.append("Successful login after failures (+25)")

    # Privileged account indicator
    privileged_accounts = {
        "administrator",
        "admin",
        "root"
    }

    if username in privileged_accounts:
        score += 15
        reasons.append("Privileged account name (+15)")

    # Keep scoring bounded
    score = min(score, 100)

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": score,
        "risk_severity": severity,
        "risk_reasons": reasons
    }
