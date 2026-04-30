// UNC2814 C2 and attacker-controlled IP
#event_simpleName = NetworkConnectIP4
| RemoteAddressIP4 = /^(130\.94\.6\.228|38\.180\.205\.14|38\.60\.194\.21|38\.54\.112\.184|38\.60\.171\.242|195\.123\.211\.70|202\.59\.10\.122|38\.60\.252\.66|45\.76\.184\.214|45\.90\.59\.129)$/
| groupBy([ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort],
    function=([count(aid, as=EventCount), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]))
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| sort(LastSeen, order=desc)
