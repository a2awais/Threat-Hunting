// Hunt:         Transfer Utilities Making Public Network Connections
// Rationale:    Network-layer view: catches obfuscated or wrapped command lines and gives destination context for pivoting.
//               Network and process events are unioned and paired per process on aid + process ID.
//               The process side is pre-filtered to transfer tools, so the union stays small.
// MITRE ATT&CK: T1048, T1567.002, T1071.001
// ----------------------------------------------------------------------------
(
  // Outbound IPv4, public only (RFC1918, loopback, link-local, CGNAT, multicast/reserved excluded)
  (#event_simpleName=NetworkConnectIP4 event_platform=Win
     RemoteAddressIP4!=/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|23[0-9]\.|255\.|0\.)/)
  // Outbound IPv6, public only (loopback, link-local, ULA, multicast excluded)
  or (#event_simpleName=NetworkConnectIP6 event_platform=Win
     RemoteAddressIP6!=/^(::1$|::$|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:|ff[0-9a-f]{2}:)/i)
  // Transfer-tool process starts (provides image / command line)
  or (#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
     (FileName=/^(curl|wget|rclone|winscp|pscp|scp|sftp|azcopy|aws|gcloud|ftp)\.exe$/i
      // Renamed copies found with Query 1b: add their hashes here
      // or SHA256HashData=/^(<sha256_1>|<sha256_2>)$/i
     ))
)
// Normalize the process key: network events reference the process via ContextProcessId
| case {
    #event_simpleName=NetworkConnectIP4
      | pid := ContextProcessId | RemoteIP := RemoteAddressIP4 | NetTs := @timestamp;
    #event_simpleName=NetworkConnectIP6
      | pid := ContextProcessId | RemoteIP := RemoteAddressIP6 | NetTs := @timestamp;
    * | pid := TargetProcessId;
  }
| groupBy([aid, pid], limit=max, function=[
    selectLast([ComputerName, UserSid, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData]),
    count(RemoteIP, as=Conns),
    min(NetTs, as=FirstConn),
    max(NetTs, as=LastConn),
    collect([RemoteIP], limit=10),
    collect([RemotePort], limit=10)
  ])
// Keep only processes seen both starting (image known) and connecting
| Conns > 0
| ImageFileName = *
// ---- Tune exclusions here ----
// | ParentBaseFileName!=/^(<known_automation_parent>)\.exe$/i
// | CommandLine!=/<trusted_destination>/i

| FirstConn := formatTime("%Y-%m-%d %H:%M:%S", field=FirstConn)
| LastConn  := formatTime("%Y-%m-%d %H:%M:%S", field=LastConn)
| sort(Conns, order=desc, limit=500)
