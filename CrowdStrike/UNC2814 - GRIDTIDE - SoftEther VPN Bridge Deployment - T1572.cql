// Detects process execution where the image path or command line references SoftEther components.

#event_simpleName = ProcessRollup2
| ImageFileName = /(?i)hamcore|vpn_bridge|softether|vpnclient|vpnbridge/
| CommandLine = /(?i)hamcore\.se2|vpn_bridge\.config|vmlog|fire\b/
| groupBy([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData])
