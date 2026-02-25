// DNS request to sheets.googleapis.com originating from a non-browser process. Core GRIDTIDE C2 mechanism

#event_simpleName = DnsRequest
| DomainName = /(?i)sheets\.googleapis\.com/
| ContextBaseFileName != /(?i)chrome|firefox|msedge|safari|opera|brave/
// | groupBy([ComputerName, UserName, FileName, DomainName])
