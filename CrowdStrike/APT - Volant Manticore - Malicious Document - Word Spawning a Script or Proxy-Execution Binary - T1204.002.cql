// Title:         Volant Manticore - Malicious Document - Word Spawning a Script or Proxy-Execution Binary
// Rationale:     Finds Word launching a shell, script host, or LOLBin. This is the visible result of macro execution in the actor's Word-based delivery.
// MITRE ATT&CK:  T1204.002, T1059.001, T1059.003, T1059.005, T1218
// Ref:           https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/
//                https://blog.checkpoint.com/security/volant-manticore-new-iranian-threat-group-expands-cyber-espionage-across-europe-and-the-middle-east/
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^winword\.exe$/i
| ImageFileName=/\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$/i
| table([@timestamp, ComputerName, UserName, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, ParentProcessId, SHA256HashData])
