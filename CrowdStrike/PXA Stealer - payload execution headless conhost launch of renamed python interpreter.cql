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
