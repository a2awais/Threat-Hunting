// T1112: Modify Registry — Enabling WDigest via registry change.
// T1003.001: OS Credential Dumping: LSASS Memory — Primary technique.
// T1556.004: Modify Authentication Process: Network Provider.

// Storm-1175 - Medusa - WDigest Enablement Followed by LSASS Credential Dumping

#event_simpleName = AsepValueUpdate OR #event_simpleName=RegSystemConfigValueUpdate
| RegObjectName="*\\Control\\SecurityProviders\\WDigest*"
| RegValueName="UseLogonCredential"
| in(field="RegStringValue", values=["0","0x1","0x00000001","00000001","1","true"])
| rename(ContextTimeStamp, as=WDigestTime)
| rename(ContextProcessId, as=RegistryContextPID)
| rename(RegObjectName, as=WDigestRegistryPath)
| rename(RegStringValue, as=WDigestValue)

| join(
  {
    #event_simpleName=ProcessRollup2
    | (ImageFileName = /(?i)(taskmgr\.exe|procdump(?:64)?\.exe|mimikatz\.exe|nanodump\.exe)/
       AND CommandLine = /(?i)(lsass|MiniDump|comsvcs\.dll|sekurlsa|procdump)/)
    | rename(ContextTimeStamp, as=ActivityTime)
    | rename(ImageFileName, as=ActivityProcess)
    | rename(CommandLine, as=ActivityCommand)
    | rename(ParentImageFileName, as=ActivityParent)
    | rename(UserName, as=ActivityUser)
  },
  field=aid
)
| test(ActivityTime >= WDigestTime)
| test(ActivityTime <= WDigestTime + 21600000000)  /* 6 hours — confirm units work in your env */
| table(ComputerName, WDigestTime, WDigestRegistryPath, WDigestValue, ActivityTime, ActivityProcess, ActivityCommand, ActivityParent, ActivityUser)
| sort(Score, order=desc)
