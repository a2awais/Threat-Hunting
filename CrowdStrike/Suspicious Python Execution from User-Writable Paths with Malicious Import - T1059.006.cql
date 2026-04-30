// MITRE ATT&CK: T1059.006 – Command and Scripting Interpreter: Python
#event_simpleName="ProcessRollup2"
| in(field="FileName", values=[
    "python.exe",
    "python3.exe",
    "pythonw.exe",
    "py.exe"
])
// Require attacker-style execution (INLINE or USER-WRITABLE PATH)
| (
    CommandLine="* -c *"
 OR CommandLine="*\\AppData\\*"
 OR CommandLine="*\\Temp\\*"
 OR CommandLine="*\\Downloads\\*"
 OR CommandLine="*\\Users\\Public\\*"
)
// AND require malicious intent indicators
| (
    CommandLine="*import socket*"
 OR CommandLine="*import subprocess*"
 OR CommandLine="*import ctypes*"
 OR CommandLine="*import base64*"
 OR CommandLine="*import urllib*"
 OR CommandLine="*exec(*"
 OR CommandLine="*eval(*"
 OR CommandLine="*pip install*"
 OR CommandLine="*pip3 install*"
 OR CommandLine="*wget *"
 OR CommandLine="*curl *"
 OR CommandLine="*bitsadmin*"
 OR CommandLine="*powershell*"
)
// Noise reduction – developer & automation tools
| NOT in(field="ParentBaseFileName", values=[
    "code.exe",
    "pycharm64.exe",
    "idea64.exe",
    "devenv.exe",
    "msbuild.exe",
    "jenkins.exe",
    "jupyter.exe",
    "anaconda.exe",
    "spyder.exe",
    "vscode.exe",
    "conda.exe",
    "cursor.exe"
])
// Exclude SYSTEM context (safe for T1059.006)
| UserName!="SYSTEM"
| table([
    @timestamp,
    ComputerName,
    UserName,
    FileName,
    ParentBaseFileName,
    CommandLine
], limit=100000)
