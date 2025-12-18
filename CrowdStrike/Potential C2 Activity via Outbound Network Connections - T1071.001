// MITRE ATT&CK: T1071.001 – Application Layer Protocol
// Suspicious outbound network connections (possible C2)
#event_simpleName="ProcessRollup2"
// Exclude VPN / secure client traffic
| NOT CommandLine="*secureclient*"
// Join outbound network connections to process execution
| join(
    {
        in(field="#event_simpleName", values=[
            "NetworkConnectIP4",
            "NetworkConnectIP6"
        ])
        // Outbound connections only
        | ConnectionDirection=1
        // Exclude RFC1918 private IP ranges
        | NOT (
            RemoteIP="10.*"
         OR RemoteIP="192.168.*"
         OR RemoteIP="172.16.*"
         OR RemoteIP="172.17.*"
         OR RemoteIP="172.18.*"
         OR RemoteIP="172.19.*"
         OR RemoteIP="172.2*"
        )
        // Exclude benign system service
        | ContextBaseFileName!="netbiosd"
    },
    key=ContextProcessId,
    field=TargetProcessId,
    include=[
        RemoteIP,
        RemotePort,
        ContextBaseFileName,
        ConnectionDirection
    ],
    limit=100000
)
| table([
    @timestamp,
    FileName,
    ParentBaseFileName,
    ContextBaseFileName,
    RemoteIP,
    RemotePort,
    ConnectionDirection,
    CommandLine
], limit=100000)
