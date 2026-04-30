// MITRE ATT&CK: T1070.001, T1562.002, T1562.001
// Defense evasion via log, audit, and service manipulation
#event_simpleName="ProcessRollup2"
// Native admin utilities abused by attackers
| in(field="FileName", values=[
    "wevtutil.exe",
    "auditpol.exe",
    "net.exe",
    "sc.exe"
])
// Malicious intent keywords
| (
    CommandLine="*stop*"
 OR CommandLine="*clear*"
 OR CommandLine="* cl *"
 OR CommandLine="*eventlog*"
 OR CommandLine="*set*"
)
// Allow-list known enterprise tooling
| NOT (
    CommandLine="*HpTouchpointAnalyticsService*"
 OR CommandLine="*OctopusDeploy Tentacle*"
 OR CommandLine="*SolarWinds.MSP*"
 OR CommandLine="*HPAudioAnalytics*"
 OR CommandLine="*PME.Agent.PmeService*"
 OR CommandLine="*stop hpLHAgent*"
 OR CommandLine="*FlexNet Licensing Service 64*"
 OR CommandLine="*net  time*"
 OR CommandLine="*C:\\Program Files (x86)\\ManageEngine\\*"
)
// Exclude known benign parent processes
| NOT in(field="ParentBaseFileName", values=[
    "UDCInfInstaller.exe",
    "PowerMgrInst.exe",
    "Philips.MEMO.ProductExporter.exe",
    "AdODIS-installer.exe"
])
| table([
    @timestamp,
    ComputerName,
    UserName,
    FileName,
    ParentBaseFileName,
    CommandLine
], limit=2000)
