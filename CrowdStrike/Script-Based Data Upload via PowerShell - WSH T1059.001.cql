// Hunt:         Script-Based Data Upload via PowerShell - WSH  (time range: 7d)
// Rationale:    With binaries blocked, operators upload using .NET primitives and web cmdlets (WebClient.UploadFile, Invoke-RestMethod -Method Post -InFile, FtpWebRequest).
//               Logic is anchored on strong upload indicators, not webclient + URL (which mostly catches download cradles).
// MITRE ATT&CK: T1059.001, T1059.005, T1048, T1567, T1041
// ----------------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| in(field=FileName, ignoreCase=true, values=[
    "powershell.exe", "pwsh.exe", "powershell_ise.exe",
    "wscript.exe", "cscript.exe", "mshta.exe" ])
| (
    // Unambiguous .NET upload primitives
    CommandLine=/(uploadfile|uploadstring|uploaddata|uploadvalues|ftpwebrequest|multipart\/form-data|postasync)/i
    // Web cmdlets sending local content
    or (
        CommandLine=/(invoke-webrequest|invoke-restmethod|(^|\s)(iwr|irm)(\s|$))/i
        CommandLine=/(-infile|-method[\s:=]+(post|put))/i
      )
  )
// ---- Tune exclusions here ----
// | ParentBaseFileName!=/^(<known_automation_parent>)\.exe$/i
// | CommandLine!=/<trusted_internal_endpoint>/i

| Time := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
| table([Time, ComputerName, UserName, ImageFileName, CommandLine,
         ParentBaseFileName, ParentProcessId, TargetProcessId, SHA256HashData, aid],
        sortby=@timestamp, order=desc, limit=1000)
