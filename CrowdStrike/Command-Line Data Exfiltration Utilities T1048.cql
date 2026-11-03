// Hunt:         Command-Line Data Exfiltration Utilities
// Rationale:    Dual-use transfer tools (rclone, WinSCP, curl, AzCopy, AWS/gcloud CLI) are favored by ransomware affiliates and APT operators because they are signed/legitimate.
//               The hunt keys on upload-oriented flags and verbs per tool, not binary presence. Each tool has its own
// MITRE ATT&CK: T1048, T1048.002, T1048.003, T1567.002, T1537, T1197
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win

// Stage 1: cheap gate on image name
| in(field=FileName, ignoreCase=true, values=[
    "curl.exe", "wget.exe", "rclone.exe", "winscp.exe", "winscp.com",
    "pscp.exe", "scp.exe", "sftp.exe", "azcopy.exe", "aws.exe",
    "gcloud.exe", "ftp.exe", "bitsadmin.exe" ])

// Stage 2: per-tool upload logic (unmatched events are dropped by case)
| case {
    // curl: upload flags (-T / -F are case-sensitive, so kept as separate case-sensitive regexes)
    FileName=/^curl\.exe$/i
      (CommandLine=/--(upload-file|data-binary|form)/i or CommandLine=/\s-[TF]\s/ or CommandLine=/\s-d\s*@/)
      | Tool := "curl";
    // wget: POST/PUT of local content
    FileName=/^wget\.exe$/i
      CommandLine=/--(post-file|post-data|method=put|body-file)/i
      | Tool := "wget";
    // rclone: transfer verbs
    FileName=/^rclone\.exe$/i
      CommandLine=/\s(copy|sync|move|copyto|moveto)(\s|$)/i
      | Tool := "rclone";
    // WinSCP: scripted upload / sync
    FileName=/^winscp\.(exe|com)$/i
      (CommandLine=/(^|[\s"'])(put|synchronize)([\s"']|$)/i or CommandLine=/\/(command|script)/i)
      | Tool := "winscp";
    // pscp / scp / sftp: put/mput, batch mode, or user@host: remote spec (direction not guaranteed)
    FileName=/^(pscp|scp|sftp)\.exe$/i
      (CommandLine=/(^|[\s"'])(put|mput)([\s"']|$)/i or CommandLine=/\s-b\s/ or CommandLine=/@[\w.\-]+:/)
      | Tool := "pscp/scp/sftp";
    // AzCopy
    FileName=/^azcopy\.exe$/i
      CommandLine=/\s(copy|sync)(\s|$)/i
      | Tool := "azcopy";
    // AWS CLI
    FileName=/^aws\.exe$/i
      CommandLine=/(s3\s+(cp|sync|mv)|put-object)/i
      | Tool := "aws-cli";
    // gcloud storage
    FileName=/^gcloud\.exe$/i
      CommandLine=/storage\s+(cp|rsync)/i
      | Tool := "gcloud";
    // ftp.exe: put/mput or script file (-s:)
    FileName=/^ftp\.exe$/i
      (CommandLine=/(^|[\s"'])(put|mput)([\s"']|$)/i or CommandLine=/\s-s:/i)
      | Tool := "ftp";
    // bitsadmin: upload jobs only (/transfer is mostly downloads)
    FileName=/^bitsadmin\.exe$/i
      CommandLine=/\/(upload|addfile)/i
      | Tool := "bitsadmin";
  }

// ---- Tune exclusions here ----
// | ParentBaseFileName!=/^(<known_automation_parent>)\.exe$/i
// | CommandLine!=/<trusted_destination_domain>/i

| Time := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
| table([Time, ComputerName, UserName, Tool, ImageFileName, CommandLine,
         ParentBaseFileName, ParentProcessId, TargetProcessId, SHA256HashData, aid],
        sortby=@timestamp, order=desc, limit=1000)
