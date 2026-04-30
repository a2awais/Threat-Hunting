| #event_simpleName="*FileWritten*" OR #event_simpleName="ClassifiedModuleLoad"
| in(field="FileName", values=[
        "throttlestop.sys",
        "rwdrv.sys",
        "hlpdrv.sys",
        "wmp.dll"
    ]
)

// Apply in case of noice

// | NOT FilePath="*\\Windows\\System32\\*"
// | NOT FilePath="*\\Windows\\SysWOW64\\*"

| table([
    @timestamp,
    ComputerName,
    TargetImageFileName,
    FileName,
    MD5HashData,
    ImageFileName,
    SHA1HashData
], limit=100000)
