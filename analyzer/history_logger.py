import json

HISTORY_FILE = "analysis_history.json"

def log_scan(entry):
    """
    Save each APK scan result to analysis_history.json
    """
    try:
        with open(HISTORY_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        data = []

    data.append(entry)

    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=4)
