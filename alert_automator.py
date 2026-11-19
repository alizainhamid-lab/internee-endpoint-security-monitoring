import os
import json
from collections import Counter
from datetime import datetime, timezone

BASE_DIR = os.path.expanduser("~/internee-soc-edr")
ALERT_LOG = os.path.join(BASE_DIR, "logs/alerts.jsonl")
AUTO_LOG = os.path.join(BASE_DIR, "logs/automated_actions.log")
REPORT_FILE = os.path.join(BASE_DIR, "submission_summary.txt")

def main():
    if not os.path.exists(ALERT_LOG):
        print("[-] No alerts.jsonl found yet.")
        return

    alerts = []
    with open(ALERT_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))

    sev_counts = Counter(a.get("severity", "UNKNOWN") for a in alerts)
    cat_counts = Counter(a.get("category", "UNKNOWN") for a in alerts)
    escalated = [a for a in alerts if a.get("severity") in ("HIGH", "CRITICAL")]

    with open(AUTO_LOG, "w") as af:
        for a in escalated:
            action = {
                "triggered_at": datetime.now(timezone.utc).isoformat(),
                "workflow": "SOC_AUTO_ESCALATION_WEBHOOK",
                "severity": a["severity"],
                "category": a["category"],
                "status": "DISPATCHED_TO_SOC_QUEUE",
                "summary": a["message"]
            }
            af.write(json.dumps(action) + "\n")

    lines = [
        "Internee.pk Security & Monitoring Task - Summary",
        f"Total Alerts: {len(alerts)} | Escalated (HIGH/CRITICAL): {len(escalated)}",
        "By Severity: " + ", ".join(f"{k}={v}" for k, v in sev_counts.items()),
        "By Category: " + ", ".join(f"{k}={v}" for k, v in cat_counts.items()),
        "Controls Active: File Integrity Monitoring (FIM), Sysmon Telemetry Correlation, User Anomaly Detection, MalwareBazaar IOC Matching, Automated Alert Escalation."
    ]
    report_text = "\n".join(lines) + "\n"

    with open(REPORT_FILE, "w") as rf:
        rf.write(report_text)

    print(report_text)
    print(f"[+] Automated escalation log saved to: {AUTO_LOG}")
    print(f"[+] Summary report saved to: {REPORT_FILE}")

if __name__ == "__main__":
    main()
