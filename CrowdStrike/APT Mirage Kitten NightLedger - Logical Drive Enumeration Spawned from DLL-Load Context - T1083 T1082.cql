// ----------------------------------------------------------------------------
// Mirage Kitten NightLedger — Logical Drive Enumeration Spawned from DLL-Load Context
// Rationale:   Detects NightLedger Command 75, which enumerates logical drives
//              as a pre-exfiltration reconnaissance step — identifying available
//              storage volumes before staging and uploading data via Command 70
//              (POST to C2). The query hunts for drive enumeration commands
//              (WMIC, fsutil, PowerShell variants) spawned specifically from
//              the DLL-loader process class associated with NightLedger's
//              execution chain. Drive enumeration from rundll32, regsvr32,
//              AppVShNotify.exe, or dllhost has no legitimate use case and
//              is high-confidence in this parent-process context.
// MITRE ATT&CK: T1083 — File and Directory Discovery
//               T1082 — System Information Discovery
// SEVERITY:    Medium — treat as high if parent process is AppVShNotify.exe
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ProcessCommandLine=/(logicaldisk|fsutil\s+fsinfo\s+drives|get-psdrive|\[system\.io\.driveinfo\])/i
| ParentBaseFileName=/(rundll32\.exe|regsvr32\.exe|appvshnotify\.exe|dllhost\.exe)/i
| Severity := if(regex("appvshnotify\\.exe", field=ParentBaseFileName, flags="i"), then="High", else="Medium")
| table([aid, ComputerName, FileName, ProcessCommandLine, ParentBaseFileName, ParentProcessId, UserName, Severity, @timestamp])
| sort(field=@timestamp, order=asc)
