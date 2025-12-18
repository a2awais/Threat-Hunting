// MITRE ATT&CK: T1562.001, T1070.004
// Suspicious power configuration changes via powercfg.exe
#event_simpleName="ProcessRollup2"
| FileName="powercfg.exe"
| CommandLine=/(?i)(\/hibernate\s+off|\-hibernate\s+off|\/h\s+off|\-h\s+off|\/hibernate:off|\-setacvalueindex|\-setdcvalueindex|\-change)/
| table([
    @timestamp,
    ComputerName,
    FileName,
    ParentBaseFileName,
    GrandParentBaseFileName,
    CommandLine,
    UserName
], limit=20000)
