from datetime import datetime


def create_incidents(detections, events):
    """
    Convert detections into structured SOC incidents
    with related events and investigation timelines.
    """

    incidents = []

    for index, detection in enumerate(detections, start=1):

        incident_id = f"INC-{index:04d}"

        username = detection["username"]
        source_ip = detection["source_ip"]

        start_time = detection["start_time"]
        success_time = detection["success_time"]

        related_events = events[
            (events["username"] == username)
            & (events["source_ip"] == source_ip)
            & (events["timestamp"] >= start_time)
            & (events["timestamp"] <= success_time)
        ].copy()

        timeline = []

        for _, event in related_events.iterrows():

            event_id = event["event_id"]

            if event_id == 4625:
                description = "Failed Login"

            elif event_id == 4624:
                description = "Successful Login"

            else:
                description = "Security Event"

            timeline.append({
                "timestamp": event["timestamp"],
                "event_id": event_id,
                "description": description
            })

        incident = {
            "incident_id": incident_id,
            "rule_id": detection["rule_id"],
            "rule_name": detection["rule_name"],
            "username": username,
            "source_ip": source_ip,
            "hostname": related_events.iloc[0]["hostname"],
            "failed_attempts": detection["failed_attempts"],
            "severity": detection["severity"],
            "start_time": start_time,
            "end_time": success_time,
            "duration_seconds": detection["time_window_seconds"],
            "timeline": timeline
        }

        incidents.append(incident)

    return incidents


if __name__ == "__main__":

    from parser import load_events
    from normalizer import normalize_events
    from detector import detect_authentication_attack

    file_path = "data/raw/windows_authentication.csv"

    raw_events = load_events(file_path)

    events = normalize_events(raw_events)

    detections = detect_authentication_attack(events)

    incidents = create_incidents(detections, events)

    print("\n=== SOC INCIDENTS ===\n")

    for incident in incidents:

        print(f"Incident ID: {incident['incident_id']}")
        print("--------------------------------")

        print(f"Rule: {incident['rule_id']}")
        print(f"Username: {incident['username']}")
        print(f"Source IP: {incident['source_ip']}")
        print(f"Hostname: {incident['hostname']}")
        print(f"Failed Attempts: {incident['failed_attempts']}")
        print(f"Severity: {incident['severity']}")
        print(f"Duration: {incident['duration_seconds']} seconds")

        print("\nTimeline:")

        for event in incident["timeline"]:

            print(
                f"{event['timestamp']} | "
                f"Event {event['event_id']} | "
                f"{event['description']}"
            )

        print()