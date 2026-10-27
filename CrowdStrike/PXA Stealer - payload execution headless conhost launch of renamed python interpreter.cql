// Title:        PXA Stealer - payload execution headless conhost launch of renamed python interpreter
// Rationale:    Flags conhost.exe --headless launching a renamed interpreter or decoded
//               payload (svchost.exe, synaptics.exe, certutil -decode, Users\Public,
//               AppData, Temp) together with image-named payloads (.ico, .png), bot-ID
//               markers (MRB_, DA_NEW_VER_, BOT) or a cmd/PowerShell/script-host parent.
// MITRE ATT&CK: T1564.003 — Hidden Window
//               T1036.005 — Match Legitimate Resource Name or Location
//               T1140 — Deobfuscate/Decode Files or Information
#event_simpleName = ProcessRollup2
| FileName = conhost.exe
| CommandLine = "*--headless*"
(
  CommandLine = "*svchost.exe*"
  OR CommandLine = "*synaptics.exe*"
  OR CommandLine = "*certutil -decode*"
  OR CommandLine = "*Users\\Public*"
  OR CommandLine = "*AppData\\Local*"
  OR CommandLine = "*AppData\\Roaming*"
  OR CommandLine = "*Temp*"
  OR CommandLine = "*tmp*"
)
AND
(
  CommandLine = "*.ico *"
  OR CommandLine = "*.png *"
  OR CommandLine = "*MRB_*"
  OR CommandLine = "*DA_NEW_VER_*"
  OR CommandLine = "*BOT*"
  // Adding more captures with parent process
  OR ParentBaseFileName = cmd.exe
  OR ParentBaseFileName = powershell.exe
  OR ParentBaseFileName = pwsh.exe
  OR ParentBaseFileName = wscript.exe
  OR ParentBaseFileName = cscript.exe
)
| table([
    @timestamp,
    aid,
    ComputerName,
    UserName,
    FileName,
    CommandLine,
    ParentBaseFileName
])
