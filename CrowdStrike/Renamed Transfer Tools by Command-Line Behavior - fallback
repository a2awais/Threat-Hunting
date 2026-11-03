// Hunt:         Renamed rclone / AzCopy / WinSCP by command-line behavior
// Rationale:    Covers renamed binaries (binary first seen before the range, or the event was not emitted).
//               Matches tool-specific command-line shapes on processes not named like the tool.
// MITRE ATT&CK: T1036.003, T1567.002, T1048
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName!=/^(rclone|azcopy|winscp)\.(exe|com)$/i
// Stage 1: cheap gate
| CommandLine=/(copy|sync|move|\/ini=nul)/i
// Stage 2: tool-specific shapes
| case {
    // rclone: verb + rclone-only flag or backend-prefixed option
    CommandLine=/(^|\s)(copy|sync|copyto|moveto|move)\s/i
      CommandLine=/\s--(transfers|checkers|fast-list|multi-thread-streams|no-check-certificate|auto-confirm|ignore-existing|bwlimit|max-age|min-age|max-size|min-size|stats|log-file|config|(s3|mega|sftp|ftp|webdav|drive|onedrive|dropbox|b2|azureblob|http)-[a-z0-9-]+)(\s|=|$)/i
      | LooksLike := "rclone";
    // AzCopy: verb + Azure storage endpoint (SAS URL)
    CommandLine=/(^|\s)(copy|sync)\s/i
      CommandLine=/https:\/\/[a-z0-9]+\.(blob|file|dfs)\.core\.windows\.net/i
      | LooksLike := "azcopy";
    // WinSCP: scripted run without saved config
    CommandLine=/\s\/ini=nul/i
      CommandLine=/\s\/(command|script=)/i
      | LooksLike := "winscp";
  }
// ---- Tune exclusions here ----
// | ParentBaseFileName!=/^(<known_automation_parent>)\.exe$/i

| Time := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
| table([Time, ComputerName, UserSid, UserName, LooksLike, ImageFileName, CommandLine,
         ParentBaseFileName, SHA256HashData, aid],
        sortby=@timestamp, order=desc, limit=1000)
