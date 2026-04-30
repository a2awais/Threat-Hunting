// Hunt curl or wget downloading .tar.gz archives directly into writable temp directories.

#event_simpleName = ProcessRollup2
| FileName = /(?i)^(curl|wget)$/
| CommandLine = /(?i)\.tar\.gz/
| CommandLine = /(?i)\/var\/tmp|\/tmp|\/dev\/shm/
| groupBy(
    [ComputerName, UserName, CommandLine, ImageFileName, ParentBaseFileName],
    function=[
        count(aid, as=EventCount),
        min(@timestamp, as=FirstSeen),
        max(@timestamp, as=LastSeen)
    ]
  )
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, locale=en_US, timezone=UTC)
| sort(LastSeen, order=desc)
