// Hunt:          Archive Creation Followed by External Transfer
// Rationale:     Archiving then sending data out within a short window is a hallmark of exfiltration.
//                Implemented with correlate() over three event sets: archive process → transfer-tool process → that same process's public connection, all on one aid within 2 hours.
// MITRE ATT&CK:  T1560.001, T1074.001, T1048, T1567.002
// ----------------------------------------------------------------------------
correlate(
  Archive: {
      #event_simpleName=ProcessRollup2 event_platform=Win
      (
        (FileName=/^(7z|7za|7zr|rar|winrar|tar|makecab)\.exe$/i
           CommandLine=/\.(zip|7z|rar|tar|gz|cab)(\W|$)/i)
        or (FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/compress-archive/i)
      )
      // ---- Tune exclusions here ----
      // UserName!=/<known_packaging_service_account>/i
  } include: [ComputerName, UserSid, UserName, ImageFileName, CommandLine,
              ParentBaseFileName, ProcessStartTime, TargetProcessId],

  // Optional: archive size. Makes a typed *FileWritten event mandatory (no .cab) and
  // requires the archive to be fully written before the transfer tool starts.
  // ArchiveFile: {
  //     #event_simpleName=/^(Zip|Rar|SevenZip|Tar|Gzip)FileWritten$/ event_platform=Win
  //     | ContextProcessId <=> Archive.TargetProcessId
  // } include: [TargetFileName, Size],

  Transfer: {
      #event_simpleName=ProcessRollup2 event_platform=Win
      (FileName=/^(rclone|curl|wget|winscp|pscp|scp|sftp|azcopy|aws)\.exe$/i
       // Renamed copies found with Query 1b: add their hashes here
       // or SHA256HashData=/^(<sha256_1>|<sha256_2>)$/i
      )
  } include: [ImageFileName, CommandLine, TargetProcessId, SHA256HashData],

  Connection: {
      #event_simpleName=NetworkConnectIP4 event_platform=Win
      RemoteAddressIP4!=/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|23[0-9]\.|255\.|0\.)/
      | ContextProcessId <=> Transfer.TargetProcessId
  } include: [RemoteAddressIP4, RemotePort, ContextTimeStamp],

  sequence=true, within=2h, globalConstraints=[aid]
)
// ---- Flatten the constellation (fields come back prefixed with the query name) ----
| rename(field="Archive.ComputerName", as=ComputerName)
| rename(field="Archive.UserName", as=ArchiveUser)
| rename(field="Archive.ImageFileName", as=ArchiveImage)
| rename(field="Archive.CommandLine", as=ArchiveCommand)
| rename(field="Archive.ParentBaseFileName", as=ArchiveParent)
| rename(field="Archive.ProcessStartTime", as=ArchiveStart)
| rename(field="Transfer.ImageFileName", as=TransferImage)
| rename(field="Transfer.CommandLine", as=TransferCommand)
| rename(field="Transfer.SHA256HashData", as=TransferSHA256)
| rename(field="Connection.RemoteAddressIP4", as=RemoteIP)
| rename(field="Connection.RemotePort", as=RemotePort)
| rename(field="Connection.ContextTimeStamp", as=ConnTime)
// ProcessStartTime / ContextTimeStamp are epoch seconds; convert to ms for formatTime()
| ArchiveStartMs := ArchiveStart * 1000
| ConnMs := ConnTime * 1000

// Summarize per archive event (avoids one row per connection)
| groupBy([aid, ComputerName, ArchiveUser, ArchiveUserSid, ArchiveImage, ArchiveCommand, ArchiveParent, ArchiveStartMs],
    limit=max, function=[
      count(as=TransferConns),
      min(ConnMs, as=FirstTransferMs),
      collect([TransferImage], limit=5),
      collect([TransferCommand], limit=3),
      collect([TransferSHA256], limit=5),
      collect([RemoteIP], limit=10),
      collect([RemotePort], limit=10)
    ])
| GapMin := (FirstTransferMs - ArchiveStartMs) / 60000
| ArchiveTime   := formatTime("%Y-%m-%d %H:%M:%S", field=ArchiveStartMs)
| FirstTransfer := formatTime("%Y-%m-%d %H:%M:%S", field=FirstTransferMs)
| table([ArchiveTime, ComputerName, ArchiveUser, ArchiveUserSid, ArchiveImage, ArchiveCommand, ArchiveParent,
         TransferImage, TransferCommand, TransferSHA256, RemoteIP, RemotePort,
         TransferConns, FirstTransfer, GapMin, aid],
        sortby=ArchiveStartMs, order=desc, limit=5000)
