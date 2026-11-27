// Title:         Volant Manticore - Homa Stage 1 - PowerShell Download-and-Execute from a Raw IP
// Rationale:     Description: Finds PowerShell pulling content from a bare IP address and running it in memory.
//                It also catches iex built from $PSSessionConfigurationName, which Homa Stage 1 uses.
// MITRE ATT&CK:  T1059.001, T1105, T1027
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(powershell|pwsh)\.exe$/i
| (
    CommandLine=/PSSessionConfigurationName\s*\[/i
    or (
      CommandLine=/https?:\/\/\d{1,3}(\.\d{1,3}){3}/i
      CommandLine=/(\biex\b|Invoke-Expression|DownloadString|ReadToEnd)/i
    )
  )
| table([@timestamp, ComputerName, UserName, aid, UserSid, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, ParentProcessId, SHA256HashData])
