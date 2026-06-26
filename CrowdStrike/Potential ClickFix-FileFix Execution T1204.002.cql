// -----------------------------------------------------------------------------
// Detection: Suspicious Win+R Command Execution (Explorer RunMRU)
// Purpose:
// Detects potentially suspicious commands executed through the Windows Run dialog (Win+R) by correlating RunMRU registry updates with the originating process.
//
// Threat Coverage:
// - ClickFix
// - FileFix
// - Fake CAPTCHA / Clipboard Social Engineering
// - User-driven LOLBin execution
// -----------------------------------------------------------------------------

#event_simpleName="ProcessRollup2"
| join(
    {
        // Monitor updates to Explorer Run (Win+R) history.
        #event_simpleName="RegSystemConfigValueUpdate"
        | RegObjectName="*\\Explorer\\RunMRU"

        // Ignore RunMRU ordering updates.
        | RegValueName!="MRUList"

        // Look for commands commonly associated with attacker tradecraft.
        | RegStringValue=/(?i)(powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript|bitsadmin|certutil|curl|wget|msiexec|installutil|hh|ftp|tftp|conhost|base64|http|https|:\/\/|\\\\)/
    },
    key=ContextProcessId,
    field=TargetProcessId,
    include=[
        RegObjectName,
        RegValueName,
        RegStringValue,
        RegOperationType
    ]
)
// Return process and registry context for investigation.
| table([
    @timestamp,
    ComputerName,
    UserName,
    FileName,
    ParentBaseFileName,
    CommandLine,
    RegObjectName,
    RegStringValue,
    RegValueName,
    RegOperationType    
], limit=100000)
