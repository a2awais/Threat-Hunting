# Threat-Hunting | Detection Engineering Queries  
CrowdStrike CQL + Microsoft Defender KQL

Collection of **threat hunting** and **detection queries** for:
- **CrowdStrike Falcon** (using CQL – CrowdStrike Query Language)
- **Microsoft Defender XDR** (using KQL – Kusto Query Language)

Aimed at surfacing suspicious processes, anomalous network behaviors, living-off-the-land binaries (LOLBins), persistence mechanisms, credential access, lateral movement, C2 activity, and potential **APT** behaviors. All mapped to **MITRE ATT&CK** techniques where applicable.

Queries are updated based on recent threat intelligence reports, emerging campaigns, and real-world observations.

## What's Inside

- `/CrowdStrike/` → CQL queries for Falcon Insight / LogScale / Next-Gen SIEM hunting
- `/KQL/` → KQL queries for Microsoft Defender for Endpoint, Defender XDR, and Sentinel

Most queries include:
- MITRE ATT&CK mapping
- Brief comments for use-case
- Tunable parameters (time windows, thresholds, exclusions)
