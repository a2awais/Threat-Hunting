#event_simpleName="ProcessRollup2"
| ZoneIdentifier = 3
| in(field="FilePath", values=["*\\Users\\Public\\*",
    "*\\Users\\*\\AppData\\Local\\Temp\\*",
    "*\\Users\\*\\AppData\\Local\\Temp\\*\\*",
    "*\\Users\\*\\AppData\\Local\\Temp\\*",
    "*\\Users\\*\\AppData\\Local\\Packages\\*",
    "*\\Users\\*\\AppData\\LocalLow\\*",
    "*\\Users\\*\\AppData\\Roaming\\*",
    "*\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*",
    "*\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*",
    "*\\Users\\*\\Downloads\\*",
    "*\\ProgramData\\*",
    "*\\Program Files (x86)\\*\\AppData\\*",
    "*\\Windows\\Temp\\*",
    "*\\PerfLogs\\*"
])
| join(
    {
        #event_simpleName="ClassifiedModuleLoad" OR #event_simpleName="UnsignedModuleLoad"
        | in(field="ImageFileName", values=[
            "*\\Users\\Public\\*",
            "*\\Users\\*\\AppData\\Local\\Temp\\*",
            "*\\Users\\*\\AppData\\Roaming\\*",
            "*\\Users\\*\\Downloads\\*",
            "*\\ProgramData\\*",
            "*\\Windows\\Temp\\*",
            "*\\PerfLogs\\*",
            "*\\AppData\\LocalLow\\*",
            "*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*"
        ])
        | masquerade:= if(FileName!=OriginalFilename, then=1, else=0)
        | masquerade = 1
        | rename(field="OriginalFilename", as="Flag_DLLOriginalFilename")
    },
    key=ContextProcessId,
    field=TargetProcessId,
    include=[FileName, TargetImageFileName, Flag_DLLOriginalFilename, ImageFileName, SHA256HashData, ReferrerUrl, Technique],
    limit=200000
)
| groupBy([ComputerName, ParentBaseFileName, FileName, OriginalFilename, Flag_DLLOriginalFilename, TargetImageFileName, ImageFileName, SHA256HashData, ReferrerUrl, Technique, UserName], limit=200000)
