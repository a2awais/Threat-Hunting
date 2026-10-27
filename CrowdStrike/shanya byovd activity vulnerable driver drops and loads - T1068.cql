// Title:         Shanya byovd activity vulnerable driver drops and loads
// Rationale:     Flags writes and loads of the drivers Sophos tied to the Shanya-packed EDR
//                killer: ThrottleStop.sys / rwdrv.sys (a legitimate TechPowerUp driver abused
//                for kernel write access) and hlpdrv.sys (an unsigned malicious driver).
// MITRE ATT&CK:  T1068 — Exploitation for Privilege Escalation
//                T1685 — Disable or Modify Tools
// Reference:     https://www.sophos.com/en-us/blog/inside-shanya-a-packer-as-a-service-fueling-modern-attacks

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
