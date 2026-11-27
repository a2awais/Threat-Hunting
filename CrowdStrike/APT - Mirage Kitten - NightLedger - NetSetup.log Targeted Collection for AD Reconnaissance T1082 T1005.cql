// ----------------------------------------------------------------------------
// Mirage Kitten NightLedger NightLedger — NetSetup.log Targeted Collection for AD Reconnaissance
// Rationale:   Detects NightLedger Command 93, which collects
//              C:\Windows\debug\NetSetup.log alongside a process listing and
//              exfiltrates both to C2. This query hunts the collection behavior
//              in DeviceProcessEvents: shell commands (type, more, cmd /c)
//              referencing the NetSetup.log path, spawned from the DLL-loader
//              process class consistent with NightLedger's execution chain.
//              NetSetup.log contains domain name, DC hostnames, and join
//              timestamps — high-value AD recon for an espionage actor.
// MITRE ATT&CK: T1082 — System Information Discovery
//               T1005 — Data from Local System
// SEVERITY:    High
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ProcessCommandLine=/netsetup\.log/i
| ProcessCommandLine=/(type\s|findstr|get-content|gc\s|cat\s|more\s)/i
// Exclude legitimate domain-join/system processes that touch this file as part of normal operation
| FileName!=/^(netsetup\.exe|netdom\.exe|svchost\.exe|lsass\.exe|wininit\.exe)$/i
| table([aid, ComputerName, FileName, ProcessCommandLine, ParentBaseFileName, UserName, @timestamp])
| sort(field=@timestamp, order=asc)
