// Matches the observed GRIDTIDE initial execution pattern:
// a short alphanumeric binary dropped in /var/tmp/ (confirmed as xapt) spawning a shell and running id along with nohup persistence launcher.

#event_simpleName = ProcessRollup2
| ImageFileName = /(?i)\/var\/tmp\/[a-z0-9]{1,10}$/
| CommandLine = /(?i)sh\s+-c\s+id|nohup\s+\.\/[a-z0-9]{1,10}|sh\s+-c\s+id\s+2>&1/
| groupBy([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
