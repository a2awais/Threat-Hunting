// Title:         Volant Manticore - Homa Framework - PowerShell Compiling XOR-Decoded JScript
// Rationale:     Finds PowerShell compiling JScript in memory with Add-Type and XOR-decoding its payload. This matches the Homa loader's documented behaviour.
// MITRE ATT&CK:  T1059.001, T1059.007, T1027
// Ref:           https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/
//                https://blog.checkpoint.com/security/volant-manticore-new-iranian-threat-group-expands-cyber-espionage-across-europe-and-the-middle-east/
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(powershell|pwsh)\.exe$/i
| CommandLine=/Add-Type.*JScript/i
| CommandLine=/(bxor|Xor-Decode)/i
| table([@timestamp, ComputerName, UserName, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, ParentProcessId, SHA256HashData])
