import pandas as pd


FAILED_LOGIN_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60


def detect_authentication_attack(events):
    """
    Detect multiple failed logins followed by a successful login.

    Rule:
    - Multiple Event ID 4625
    - Same username
    - Same source IP
    - Followed by Event ID 4624
    - Within the configured time window
    - Generate only one detection for the same authentication burst
    """

    events = events.sort_values("timestamp").reset_index(drop=True)

    incidents = []
    processed_incidents = set()

    failed_events = events[events["event_id"] == 4625]

    for _, failed_event in failed_events.iterrows():

        username = failed_event["username"]
        source_ip = failed_event["source_ip"]
        start_time = failed_event["timestamp"]

        incident_key = (username, source_ip)

        # Prevent duplicate detections
        if incident_key in processed_incidents:
            continue

        window_end = start_time + pd.Timedelta(
            seconds=TIME_WINDOW_SECONDS
        )

        related_events = events[
            (events["username"] == username)
            & (events["source_ip"] == source_ip)
            & (events["timestamp"] >= start_time)
            & (events["timestamp"] <= window_end)
        ]

        failed_count = len(
            related_events[related_events["event_id"] == 4625]
        )

        successful_logins = related_events[
            related_events["event_id"] == 4624
        ]

        if (
            failed_count >= FAILED_LOGIN_THRESHOLD
            and not successful_logins.empty
        ):

            success_event = successful_logins.iloc[0]

            incidents.append({
                "rule_id": "AUTH-001",
                "rule_name": "Failed Logins Followed By Successful Login",
                "username": username,
                "source_ip": source_ip,
                "failed_attempts": failed_count,
                "successful_login": True,
                "start_time": start_time,
                "success_time": success_event["timestamp"],
                "time_window_seconds": (
                    success_event["timestamp"] - start_time
                ).total_seconds(),
                "severity": "HIGH"
            })

            processed_incidents.add(incident_key)

    return incidents


if __name__ == "__main__":

    from parser import load_events
    from normalizer import normalize_events

    file_path = "data/raw/windows_authentication.csv"

    raw_events = load_events(file_path)

    events = normalize_events(raw_events)

    detections = detect_authentication_attack(events)

    print("\n=== DETECTION RESULTS ===\n")

    if not detections:
        print("No suspicious authentication activity detected.")

    else:
        for incident in detections:

            print("🚨 AUTHENTICATION DETECTION")
            print("--------------------------------")
            print(f"Rule ID: {incident['rule_id']}")
            print(f"Rule: {incident['rule_name']}")
            print(f"Username: {incident['username']}")
            print(f"Source IP: {incident['source_ip']}")
            print(f"Failed Attempts: {incident['failed_attempts']}")
            print(f"Successful Login: {incident['successful_login']}")
            print(
                f"Time Window: "
                f"{incident['time_window_seconds']} seconds"
            )
            print(f"Severity: {incident['severity']}")
            print()