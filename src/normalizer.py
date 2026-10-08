import pandas as pd


def normalize_events(events):
    """
    Convert raw security events into a standard SOC event format.
    """

    normalized = pd.DataFrame()

    normalized["timestamp"] = events["timestamp"]
    normalized["event_id"] = events["event_id"]
    normalized["username"] = events["user"]
    normalized["source_ip"] = events["source_ip"]
    normalized["hostname"] = events["host"]
    normalized["status"] = events["status"]

    # Keep the original event for future investigation
    normalized["raw_event"] = events.to_dict(orient="records")

    return normalized


if __name__ == "__main__":
    from parser import load_events

    file_path = "data/raw/windows_authentication.csv"

    events = load_events(file_path)

    normalized_events = normalize_events(events)

    print("\n=== NORMALIZED SOC EVENTS ===\n")
    print(normalized_events)

    print("\n=== NORMALIZED COLUMNS ===")
    print(normalized_events.columns.tolist())