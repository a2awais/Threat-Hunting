// MITRE ATT&CK: T1615 – Group Policy Discovery
#event_simpleName="ProcessRollup2"
| in(field="FileName", values=[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wmic.exe",
    "rundll32.exe"
])
// High-confidence GPO discovery commands
| (
    // Native GPO / RSOP discovery
    CommandLine = "*gpresult*"
 or CommandLine = "*gpresult /r*"
 or CommandLine = "*gpresult /z*"
 or CommandLine = "*rsop.msc*"
 or CommandLine = "*secedit /export*"
 or CommandLine = "*secedit /analyze*"

    // Registry-based policy enumeration
 or CommandLine = "*reg query HKLM\\Software\\Policies*"
 or CommandLine = "*reg query HKCU\\Software\\Policies*"

    // PowerShell-based GPO discovery (APT & ransomware-preferred)
 or CommandLine = "*Get-GPO*"
 or CommandLine = "*Get-GPInheritance*"
 or CommandLine = "*Get-GPResultantSetOfPolicy*"
 or CommandLine = "*Get-DomainGPO*"
 or CommandLine = "*Get-DomainGPOLocalGroup*"

    // LDAP-based policy discovery
 or CommandLine = "*ldapsearch*"
 or CommandLine = "*groupPolicyContainer*"
)

// Reduce OS / admin noise
| NOT in(field="ParentBaseFileName", values=[
    "gpscript.exe",
    "svchost.exe",
    "mmc.exe",
    "Microsoft.Management.Infrastructure.Native.exe"
])
| table([
    @timestamp,
    ComputerName,
    UserName,
    FileName,
    ParentBaseFileName,
    CommandLine,
    FilePath
], limit=100000)
