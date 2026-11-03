// Hunt:         Potential C2 Activity via Outbound Network Connections  (time range: 1d)
// Rationale:    Implants beacon over web and application-layer protocols from processes that normally have no business reaching the internet.
//               The hunt lists every process with public outbound connections, then adds context so analysts can triage at a glance.
// MITRE ATT&CK: T1071 - Application Layer Protocol
//               T1071.001 - Web Protocols
//               T1571 - Non-Standard Port
// ----------------------------------------------------------------------------
// Stage 0: process names that make public outbound connections from only a few hosts
defineTable(
  name="rareOutbound",
  query={
    (
      // IPv4: exclude RFC1918, loopback, link-local, CGNAT, multicast/reserved
      (#event_simpleName=NetworkConnectIP4
         RemoteAddressIP4!=/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|23[0-9]\.|255\.|0\.)/)
      // IPv6: exclude loopback, unspecified, link-local, ULA, multicast
      or (#event_simpleName=NetworkConnectIP6
         RemoteAddressIP6!=/^(::1$|::$|fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:|ff[0-9a-f]{2}:)/i)
    )
    ConnectionDirection=0
    ContextBaseFileName=*
    // Benign system service (macOS NetBIOS daemon)
    ContextBaseFileName!=/^netbiosd$/i
    | case {
        #event_simpleName=NetworkConnectIP4 | RemoteIP := RemoteAddressIP4;
        #event_simpleName=NetworkConnectIP6 | RemoteIP := RemoteAddressIP6;
        *
      }
    | groupBy([ContextBaseFileName], limit=max, function=[
        count(aid, distinct=true, as=Hosts),
        count(as=Conns),
        count(RemoteIP, distinct=true, as=DistinctDests),
        min(@timestamp, as=FirstConnMs),
        max(@timestamp, as=LastConnMs),
        collect([RemoteIP], limit=5),
        collect([RemotePort], limit=5)
      ])
    // Rarity threshold: tune to fleet size
    | Hosts <= 5
  },
  include=[ContextBaseFileName, Hosts, Conns, DistinctDests, FirstConnMs, LastConnMs, RemoteIP, RemotePort]
)
// Main stream: executions of those rare process names
| #event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| match(file="rareOutbound", field=FileName, column=ContextBaseFileName, ignoreCase=true,
        include=[Hosts, Conns, DistinctDests, FirstConnMs, LastConnMs, RemoteIP, RemotePort], strict=true)

// Exclude Cisco Secure Client / AnyConnect by image path (the original excluded on CommandLine,
// which any process can spoof by adding the string to its arguments)
| ImageFileName!=/(\\Cisco\\Cisco (Secure Client|AnyConnect Secure Mobility Client)\\|\/opt\/cisco\/(secureclient|anyconnect)\/)/i

// ---- Tune exclusions here ----
// | ImageFileName!=/\\<approved_agent>\.exe$/i
// | RemoteIP!=/^<trusted_prefix>/

| FirstConn := formatTime("%Y-%m-%d %H:%M:%S", field=FirstConnMs)
| LastConn  := formatTime("%Y-%m-%d %H:%M:%S", field=LastConnMs)
| table([@timestamp, ComputerName, UserName, ImageFileName, ParentBaseFileName, CommandLine,
         RemoteIP, RemotePort, Hosts, Conns, DistinctDests, FirstConn, LastConn, SHA256HashData, aid, TargetProcessId],
        sortby=Hosts, order=asc, limit=1000)
