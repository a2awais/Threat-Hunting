// Blinder Tunnel - MicrosoftRuntime Run Key Persistence
// Rationale:   Detects persistence associated with Blinder Tunnel malware,
//              which creates a "MicrosoftRuntime" value under the current
//              user's Run registry key. The value points to a masquerading
//              RuntimeBroker.exe binary staged in a user-writable
//              %LOCALAPPDATA%\Microsoft\RuntimeBrokers\ directory,
//              enabling execution at user logon. The value name and path
//              combination provide a high-fidelity indicator with low
//              expected enterprise prevalence.
// MITRE ATT&CK: T1547.001 — Registry Run Keys / Startup Folder
// SEVERITY:    Medium-High — investigate for associated Blinder Tunnel
//              activity and C2 communications.
// Ref:         https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/
// Ref:         https://github.com/NextronSystems/iocs/tree/master/reports/A%20New%20Variant%20of%20Blinder%20Tunnel%20with%20Zero%20AV%20Detection
// ----------------------------------------------------------------------------
// Registry persistence via MicrosoftRuntime autorun value
"#event_simpleName" = *Reg*
| RegObjectName="*\\Microsoft\\Windows\\CurrentVersion\\Run*"
| RegValueName=/.*(?i)MicrosoftRuntime.*/
| table([@timestamp, ComputerName, UserName, RegObjectName, RegValueName, RegStringValue])
