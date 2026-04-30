// MITRE: T1566.001 - Phishing: Spearphishing Attachment
#event_simpleName=ProcessRollup2
| in(field=FileName, values=[
    "powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe",
    "regsvr32.exe","certutil.exe","bitsadmin.exe","wmic.exe","expand.exe"
])
| (
    CommandLine="*-EncodedCommand*" OR
    CommandLine="*FromBase64String*" OR
    CommandLine="*ExecutionPolicy Bypass*" OR
    CommandLine="*Invoke-WebRequest*" OR
    CommandLine="*Invoke-RestMethod*" OR
    CommandLine="*DownloadString*" OR
    CommandLine="*DownloadFile*" OR
    CommandLine="*net.webclient*" OR
    CommandLine="*iex*" OR
    CommandLine="*certutil -decode*" OR
    CommandLine="*bitsadmin /transfer*" OR
    CommandLine="*http://*" OR
    CommandLine="*https://*"
)
| (
    CommandLine="*\\Downloads\\*" OR
    CommandLine="*\\Temp\\*" OR
    CommandLine="*\\AppData\\Local\\Temp\\*" OR
    CommandLine="*\\Desktop\\*" OR
    CommandLine="*\\INetCache\\*"
)
| in(field=ParentBaseFileName, values=[
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe",
    "acrord32.exe","acrord64.exe","explorer.exe",
    "msedge.exe","chrome.exe","firefox.exe"
])
// | UserName!="SYSTEM"
| table([
    @timestamp,
    ComputerName,
    UserName,
    ParentBaseFileName,
    FileName,
    CommandLine,
    SHA256HashData
])
| sort(@timestamp, desc)
