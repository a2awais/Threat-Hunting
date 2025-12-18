// MITRE ATT&CK: T1574.002 – DLL Search Order Hijacking
// consent.exe suspicious module load (Classified telemetry)
#event_simpleName="ClassifiedModuleLoad"
// consent.exe as the loading process
| TargetImageFileName="*\\consent.exe"
// | FilePath != "*\\Windows\\System32\\"
| in(field="FileName", values=[
        "msimg32.dll",
        "version.dll",
        "rtworkq.dll",
        "rtworkq.dll",
        "wmsgapi.dll",
        "sh4nya_fuckav.dll",
        "shanya.dll",
        "*sh4nya*",
        "*shanya*"
    ])
| table([
    @timestamp,
    ComputerName,
    TargetImageFileName,
    FileName,
    MD5HashData,
    ImageFileName,
    SHA1HashData
], limit=100000)
