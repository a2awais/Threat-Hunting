// MITRE ATT&CK: T1053.005, T1059, T1027
// Suspicious scheduled task persistence using LOLBins
#event_simpleName="ScheduledTaskRegistered"
// Benign-looking task names used for camouflage
| (
    TaskName="*update*"
 OR TaskName="*maintask*"
 OR TaskName="*sync*"
 OR TaskName="*backup*"
 OR TaskName="*logon*"
 OR TaskName="*\\Microsoft\\Windows\\EnterpriseMgmt*"
)
// Suspicious execution via LOLBins or encoded payloads
| (
    TaskExecCommand="*powershell*"
 OR TaskExecCommand="*cmd*"
 OR TaskExecCommand="*rundll32*"
 OR TaskExecCommand="*certutil*"
 OR TaskExecCommand="*bitsadmin*"
 OR TaskExecCommand="*mshta*"
 OR TaskExecCommand="*wscript*"
 OR TaskExecCommand="*cscript*"
 OR TaskExecArguments="*-enc*"
 OR TaskExecArguments="*Invoke-*"
)
// Exclude SYSTEM and machine accounts
| NOT (
    TaskAuthor="*$"
 OR TaskAuthor="*SYSTEM*"
)
| table([
    @timestamp,
    ComputerName,
    TaskName,
    TaskExecCommand,
    TaskExecArguments,
    TaskAuthor
], limit=20000)
