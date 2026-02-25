// hunts for SSH being invoked from an unusual process lineage, not from interactive shells or expected automation - Just as a pivot indicator.

#event_simpleName = ProcessRollup2
| FileName = /^ssh$/i
| ParentBaseFileName != /bash|zsh|sh|tmux|screen|sshd/i
| UserName != /root/i
| groupBy([ComputerName, UserName, ParentBaseFileName, CommandLine, RemoteAddressIP4],
    function=([count(aid, as=EventCount), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]))
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| sort(LastSeen, order=desc)
