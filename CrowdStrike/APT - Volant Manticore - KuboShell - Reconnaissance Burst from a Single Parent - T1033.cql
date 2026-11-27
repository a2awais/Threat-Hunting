// Title:         Volant Manticore - KuboShell - Reconnaissance Burst from a Single Parent
// Rationale:     Finds one parent process launching three or more different reconnaissance tools.
//                The tools are the ones KuboShell is reported to run: quser, whoami, ipconfig, route, netstat, nslookup for Kerberos records, and net for Domain Admins.
//                Grouping by parent keeps this high-fidelity: a single whoami on its own won't trigger it.
// MITRE ATT&CK:  T1033, T1016, T1049, T1069.002, T1018
// Ref:           https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/
//                https://blog.checkpoint.com/security/volant-manticore-new-iranian-threat-group-expands-cyber-espionage-across-europe-and-the-middle-east/
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(quser|whoami|ipconfig|route|netstat|nslookup|net|net1)\.exe$/i
| groupBy([aid, ComputerName, UserName, ParentBaseFileName, ParentProcessId],
    function=[
      count(ImageFileName, distinct=true, as=DistinctTools),
      collect([ImageFileName, CommandLine]),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ])
| test(DistinctTools >= 3)
| sort(DistinctTools, order=desc)
