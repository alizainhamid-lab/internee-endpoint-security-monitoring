import os
import json
import time
import hashlib
from datetime import datetime, timezone

WATCH_DIR = os.path.expanduser("~/internee-soc-edr/monitored_dir")
BASELINE_FILE = os.path.expanduser("~/internee-soc-edr/data/fim_baseline.json")
ALERT_LOG = os.path.expanduser("~/internee-soc-edr/logs/alerts.jsonl")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def emit_alert(severity, category, message, details):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "Internee.pk-EDR-FIM",
        "severity": severity,
        "category": category,
        "message": message,
        "details": details
    }
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[ALERT | {severity}] {category}: {message} -> {details}")

def scan_dir():
    state = {}
    for root, _, files in os.walk(WATCH_DIR):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                stat = os.stat(full_path)
                state[full_path] = {
                    "sha256": sha256_file(full_path),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime
                }
            except FileNotFoundError:
                pass
    return state

def main():
    if not os.path.exists(BASELINE_FILE):
        baseline = scan_dir()
        with open(BASELINE_FILE, "w") as f:
            json.dump(baseline, f, indent=2)
        print(f"[+] Baseline created for {WATCH_DIR} ({len(baseline)} files).")
        return

    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    current = scan_dir()

    for path, meta in current.items():
        if path not in baseline:
            emit_alert("MEDIUM", "FIM_NEW_FILE", "New file detected in monitored directory", {"path": path, "sha256": meta["sha256"]})
        elif meta["sha256"] != baseline[path]["sha256"]:
            emit_alert("HIGH", "FIM_MODIFIED", "File content/hash modified", {
                "path": path,
                "old_sha256": baseline[path]["sha256"],
                "new_sha256": meta["sha256"]
            })

    for path in baseline:
        if path not in current:
            emit_alert("HIGH", "FIM_DELETED", "Monitored file deleted", {"path": path, "old_sha256": baseline[path]["sha256"]})

    with open(BASELINE_FILE, "w") as f:
        json.dump(current, f, indent=2)

if __name__ == "__main__":
    main()
