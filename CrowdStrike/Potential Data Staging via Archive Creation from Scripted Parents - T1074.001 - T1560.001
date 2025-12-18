// MITRE ATT&CK: T1074.001, T1560.001
// Suspicious data staging via archive creation
#event_simpleName="ProcessRollup2"
// Common attacker-controlled or LOLBin parents
| in(field="ParentBaseFileName", values=[
    "powershell.exe",
    "cmd.exe",
    "7z.exe",
    "winrar.exe",
    "explorer.exe"
])
// Join with file write events from the same process
| join(
    {
        #event_simpleName=*FileWritten*
        // User-writable and staging directories
        | FilePath="*\\Users\\Public\\*"
         OR FilePath="*\\ProgramData\\*"
         OR FilePath="*\\Windows\\Temp\\*"
         OR FilePath="*\\PerfLogs\\*"
        // Archive formats commonly used for staging
        | FileName="*.zip"
         OR FileName="*.7z"
         OR FileName="*.rar"
         OR FileName="*.gz"
    },
    key=ContextProcessId,
    field=TargetProcessId,
    include=[
        FileName,
        FilePath,
        ContextBaseFileName,
        MD5HashData
    ],
    limit=100000
)
| table([
    @timestamp,
    ComputerName,
    UserName,
    ParentBaseFileName,
    ContextBaseFileName,
    ImageFileName,
    CommandLine,
    FileName,
    FilePath,
    SHA256HashData,
    MD5HashData
], limit=10000)
