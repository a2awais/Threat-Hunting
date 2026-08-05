// =============================================================================
// Ref: https://securelist.com/mirage-kitten-new-tools/120811/
// Mirage Kitten NightLedger Backdoor: DLL Search-Order Hijack (SspiCli.dll via AppVShNotify.exe)
// Rationale:   Detects NightLedger's delivery mechanism: the implant is
//              compiled as a malicious SspiCli.dll and co-located with
//              AppVShNotify.exe (a legitimate Microsoft App-V binary).
//              AppVShNotify.exe imports RPCRT4.dll, which delay-loads
//              SspiCli.dll when an authenticated RPC call is made — loading
//              the implant from the working directory rather than System32.
//              Any load of SspiCli.dll by AppVShNotify.exe from outside
//              canonical Windows system paths is a binary-confidence indicator
//              with near-zero false positive rate in production environments.
// MITRE: T1574.001 — DLL Search Order Hijacking
// Severity: CRITICAL
// =============================================================================
#event_simpleName=ClassifiedModuleLoad
| FileName=/sspicli\.dll/i
// Exclude any load from a canonical Windows system directory
| FilePath!=/^c:\\windows\\(system32|syswow64|winsxs|assembly|microsoft\.net)|^c:\\program files/i
// Confirm the loading process (same aid + process instance) is AppVShNotify.exe
| selfJoinFilter(field=[aid, TargetProcessId], where=[{#event_simpleName=ProcessRollup2 FileName=/appvshnotify\.exe/i}])
| table([aid, ComputerName, FileName, FilePath, SHA256HashData, TargetProcessId, @timestamp])
| sort(field=@timestamp, order=asc)
