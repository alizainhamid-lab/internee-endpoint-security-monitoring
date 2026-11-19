# Endpoint Security, Threat Correlation & Automated Monitoring

A lightweight, Python-based Blue Team / SOC monitoring and alerting engine built for an **Internee.pk** cybersecurity internship task on a single **Kali Linux (Oracle VirtualBox)** environment.

## Objective
Protect devices and servers from unauthorized changes, suspicious activity, and malware indicators by combining File Integrity Monitoring (FIM), Sysmon telemetry correlation, user anomaly checks, MalwareBazaar threat intelligence matching, and automated alert escalation.

## Architecture & Modules
- **`fim_monitor.py`**: Generates and verifies SHA-256 baselines for monitored files (`monitored_dir/`), detecting unauthorized modifications (`FIM_MODIFIED`), new file creations (`FIM_NEW_FILE`), and deletions (`FIM_DELETED`).
- **`soc_correlator.py`**: Correlates Sysmon-style events (`Event ID 1` process creation, `Event ID 3` network connections), user behavior anomalies (failed login spikes, off-hours privilege escalation), and **MalwareBazaar** SHA-256 IOCs (`data/malwarebazaar_iocs.json`).
- **`alert_automator.py`**: Reads structured alert telemetry from `logs/alerts.jsonl`, dispatches `HIGH` and `CRITICAL` alerts to an escalation log (`logs/automated_actions.log`), and produces a summary report (`submission_summary.txt`).

## Lab Environment
- **OS**: Kali Linux (x86_64) running in Oracle VirtualBox (~3.8 GiB RAM, 17G free disk space)
- **Language**: Python 3 (standard library: `os`, `json`, `hashlib`, `collections`, `datetime`)

## Usage

### 1. File Integrity Monitoring (FIM)
```bash
# Create initial baseline
python3 ~/internee-soc-edr/fim_monitor.py

# Detect changes against baseline
python3 ~/internee-soc-edr/fim_monitor.py
