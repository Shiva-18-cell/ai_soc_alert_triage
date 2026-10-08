import pandas as pd


def load_events(file_path):
    """
    Load security events from a CSV file
    and convert timestamps into datetime objects.
    """

    events = pd.read_csv(file_path)

    events["timestamp"] = pd.to_datetime(events["timestamp"])

    return events


if __name__ == "__main__":
    file_path = "data/raw/windows_authentication.csv"

    events = load_events(file_path)

    print("\n=== SOC EVENT DATA ===\n")
    print(events)

    print("\n=== EVENT COUNT ===")
    print(len(events))

    print("\n=== DATA TYPES ===")
    print(events.dtypes)