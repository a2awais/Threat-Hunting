// GRIDTIDE achieves persistence by creating /etc/systemd/system/xapt.service and launching from /usr/sbin/xapt.
// Hunts for any newly created .service files in systemd paths by non-standard processes - directly matching the persistence path.

#event_simpleName = ProcessRollup2
| ImageFileName = /(?i)\/usr\/sbin\/[a-z0-9]{1,10}$/
| CommandLine = /(?i)\/etc\/systemd\/system\/[a-z0-9]{1,10}\.service/
| groupBy(
    [ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData],
    function=[
        count(aid, as=EventCount),
        min(@timestamp, as=FirstSeen),
        max(@timestamp, as=LastSeen)
    ]
  )
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, locale=en_US, timezone=UTC)
| LastSeen  := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, locale=en_US, timezone=UTC)
| sort(LastSeen, order=desc)
