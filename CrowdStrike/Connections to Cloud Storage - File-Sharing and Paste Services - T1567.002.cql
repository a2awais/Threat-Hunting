// Hunt:         Connections to Cloud Storage, File-Sharing and Paste Services
// Rationale:    Flags endpoints tied to anonymous file-drop sites, paste services and chat platforms abused for exfiltration and C2.
//               Sanctioned services (Dropbox, Drive, OneDrive, Box) are left out as in the original; an optional block is included.
// MITRE ATT&CK: T1567.002, T1567.003, T1567, T1102
// ----------------------------------------------------------------------------
// Stage 0: small table of (aid, process) pairs that resolved a flagged domain
defineTable(
  name="flaggedProcs",
  query={
    #event_simpleName=DnsRequest event_platform=Win
    DomainName=/(^|\.)(mega\.nz|mega\.io|mega\.co\.nz|mediafire\.com|wetransfer\.com|we\.tl|transfernow\.net|gofile\.io|file\.io|pixeldrain\.com|sendspace\.com|wormhole\.app|transfer\.sh|tmpfiles\.org|catbox\.moe|0x0\.st|filebin\.net|ufile\.io|bashupload\.com|temp\.sh|oshi\.at|pastebin\.com|paste\.ee|rentry\.co|discord\.com|discordapp\.com|telegram\.org|t\.me)$/i
    | rename(field=ContextProcessId, as=TargetProcessId)
    | groupBy([aid, TargetProcessId], limit=max)
  },
  include=[aid, TargetProcessId]
)
// Stream: flagged DNS lookups + process starts + public IPv4 connections
| (
    (#event_simpleName=DnsRequest event_platform=Win
       DomainName=/(^|\.)(mega\.nz|mega\.io|mega\.co\.nz|mediafire\.com|wetransfer\.com|we\.tl|transfernow\.net|gofile\.io|file\.io|pixeldrain\.com|sendspace\.com|wormhole\.app|transfer\.sh|tmpfiles\.org|catbox\.moe|0x0\.st|filebin\.net|ufile\.io|bashupload\.com|temp\.sh|oshi\.at|pastebin\.com|paste\.ee|rentry\.co|discord\.com|discordapp\.com|telegram\.org|t\.me)$/i)
    or (#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win)
    or (#event_simpleName=NetworkConnectIP4 event_platform=Win
       RemoteAddressIP4!=/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|23[0-9]\.|255\.|0\.)/)
  )
// Normalize the process key: DNS and network events reference the process via ContextProcessId
| case {
    #event_simpleName=DnsRequest        | TargetProcessId := ContextProcessId | DnsTs := @timestamp;
    #event_simpleName=NetworkConnectIP4 | TargetProcessId := ContextProcessId;
    *
  }
// Keep only processes that resolved a flagged domain
| match(file="flaggedProcs", field=[aid, TargetProcessId], column=[aid, TargetProcessId], strict=true)
// Label the service (only DNS events carry DomainName; other events fall through)
| case {
    DomainName=/(^|\.)(mega\.nz|mega\.io|mega\.co\.nz)$/i | Service := "MEGA";
    DomainName=/(^|\.)mediafire\.com$/i | Service := "MediaFire";
    DomainName=/(^|\.)(wetransfer\.com|we\.tl)$/i | Service := "WeTransfer";
    DomainName=/(^|\.)transfernow\.net$/i | Service := "TransferNow";
    DomainName=/(^|\.)gofile\.io$/i | Service := "Gofile";
    DomainName=/(^|\.)file\.io$/i | Service := "File.io";
    DomainName=/(^|\.)pixeldrain\.com$/i | Service := "Pixeldrain";
    DomainName=/(^|\.)sendspace\.com$/i | Service := "Sendspace";
    DomainName=/(^|\.)wormhole\.app$/i | Service := "Wormhole";
    DomainName=/(^|\.)transfer\.sh$/i | Service := "Transfer.sh";
    DomainName=/(^|\.)tmpfiles\.org$/i | Service := "Tmpfiles";
    DomainName=/(^|\.)catbox\.moe$/i | Service := "Catbox";
    DomainName=/(^|\.)0x0\.st$/i | Service := "0x0.st";
    DomainName=/(^|\.)(filebin\.net|ufile\.io|bashupload\.com|temp\.sh|oshi\.at)$/i | Service := "Anonymous file drop";
    DomainName=/(^|\.)(pastebin\.com|paste\.ee|rentry\.co)$/i | Service := "Paste service";
    DomainName=/(^|\.)(discord\.com|discordapp\.com)$/i | Service := "Discord";
    DomainName=/(^|\.)(telegram\.org|t\.me)$/i | Service := "Telegram";
    // Optional sanctioned services (add to BOTH domain gates above to enable):
    // DomainName=/(^|\.)dropbox\.com$/i | Service := "Dropbox";
    // DomainName=/(^|\.)(drive\.google\.com|docs\.google\.com)$/i | Service := "Google Drive";
    // DomainName=/(^|\.)(onedrive\.live\.com|1drv\.ms)$/i | Service := "OneDrive";
    // DomainName=/(^|\.)box\.com$/i | Service := "Box";
    *
  }
// One row per process, combining DNS, process and network context
| groupBy([aid, TargetProcessId], limit=max, function=[
    selectLast([ComputerName, UserSid, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData]),
    count(DomainName, as=DnsHits),
    count(DomainName, distinct=true, as=DistinctDomains),
    min(DnsTs, as=FirstDnsMs),
    max(DnsTs, as=LastDnsMs),
    collect([Service], limit=5),
    collect([DomainName], limit=10),
    collect([IP4Records], limit=10),
    count(RemoteAddressIP4, as=PublicConns),
    collect([RemoteAddressIP4], limit=10),
    collect([RemotePort], limit=10)
    // Optional, only if your Windows NetworkConnectIP4 carries byte counts (validation query 6):
    // , sum(OutboundDataCount, as=OutBytes), sum(InboundDataCount, as=InBytes)
  ])
| DnsHits > 0
| default(field=ImageFileName, value="<start before range>")
// ---- Tune exclusions here ----
// | ImageFileName!=/\\(chrome|msedge|firefox|iexplore|brave|opera)\.exe$/i   // non-browser initiators only
// | ImageFileName!=/\\<approved_client>\.exe$/i
// | DomainName!=/<trusted_domain>/i

| FirstDns := formatTime("%Y-%m-%d %H:%M:%S", field=FirstDnsMs)
| LastDns  := formatTime("%Y-%m-%d %H:%M:%S", field=LastDnsMs)
| rename(field=ImageFileName, as=ProcessImage)
| rename(field=CommandLine, as=ProcessCommand)
| rename(field=ParentBaseFileName, as=ParentProcess)
| rename(field=SHA256HashData, as=ProcessSHA256)
| rename(field=Service, as=Services)
| rename(field=DomainName, as=Domains)
| rename(field=IP4Records, as=DnsAnswerIPs)
| rename(field=RemoteAddressIP4, as=RemoteIPs)
| rename(field=RemotePort, as=RemotePorts)
| table([LastDns, FirstDns, ComputerName, UserName, Services, Domains, DnsHits, DistinctDomains,
         DnsAnswerIPs, ProcessImage, ProcessCommand, ParentProcess, ProcessSHA256,
         PublicConns, RemoteIPs, RemotePorts, aid],
        sortby=LastDnsMs, order=desc, limit=5000)
