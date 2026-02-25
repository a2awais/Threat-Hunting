// hunts for the specific post-exploitation recon pattern: a non-standard parent binary executing id or whoami via a shell wrapper.
#event_simpleName = ProcessRollup2
| FileName = /^(id|whoami)$/i
| ParentBaseFileName != /bash|sh|zsh|sshd|sudo|cron|systemd/i
| CommandLine = /sh\s+-c\s+(id|whoami)/i
| groupBy([ComputerName, UserName, ParentBaseFileName, CommandLine, SHA256HashData]))
