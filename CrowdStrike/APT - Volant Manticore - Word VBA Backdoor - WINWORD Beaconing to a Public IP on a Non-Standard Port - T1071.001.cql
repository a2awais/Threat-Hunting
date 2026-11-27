// Title:         Volant Manticore - Word VBA Backdoor - WINWORD Beaconing to a Public IP on a Non-Standard Port
// Rationale:     Finds Word repeatedly connecting to the same public IP on a port other than 80 or 443.
//                This matches the Word VBA backdoor's direct HTTP beaconing on a high port.
// MITRE ATT&CK:  MITRE: T1071.001, T1059.005, T1204.002
// Ref:           https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/
//                https://blog.checkpoint.com/security/volant-manticore-new-iranian-threat-group-expands-cyber-espionage-across-europe-and-the-middle-east/
// ----------------------------------------------------------------------------
// Title:         Volant Manticore - Word VBA Backdoor - WINWORD Beaconing to a Public IP on a Non-Standard Port
// Rationale:     Finds Word repeatedly connecting to the same public IP on a port other than 80 or 443.
//                This matches the Word VBA backdoor's direct HTTP beaconing on a high port.
// MITRE ATT&CK:  MITRE: T1071.001, T1059.005, T1204.002
// Ref:           https://research.checkpoint.com/2026/volant-manticore-flying-under-the-radar/
//                https://blog.checkpoint.com/security/volant-manticore-new-iranian-threat-group-expands-cyber-espionage-across-europe-and-the-middle-east/
// ----------------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4 event_platform=Win
| ContextBaseFileName=/^winword\.exe$/i
| !in(field=RemotePort, values=["80", "443"])
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"])
| groupBy([aid, ContextProcessId, RemoteAddressIP4, RemotePort], function=[
    count(as=Connections),
    collect([ComputerName]),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)
  ], limit=max)
