// Intel: https://www.cloudsek.com/blog/reborn-in-rust-muddywater-evolves-tooling-with-rustywater-implant

#event_simpleName="ProcessRollup2"

// Office macro launch points
| in(field="ParentBaseFileName", values=[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe"
])
// Script + LOLBins used post-macro
| in(field="FileName", values=[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "wmic.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
// Dropped Files Muddy/Rusty Water IOCs from intel
    "reddit.exe", 
    "art.exe",
    "cloud.exe",
    "nginx.exe",
    "CertificationKit.ini" 
])
// Writable paths abused by MuddyWater/RustyWater
| ( FilePath = "*\\ProgramData\\*"
 or FilePath = "*\\Users\\Public\\*"
 or FilePath = "*\\AppData\\Roaming\\*"
 or FilePath = "*\\AppData\\Local\\Temp\\*"
)
| table([ComputerName, FileName, FilePath, ParentBaseFileName, CommandLine, UserName])
