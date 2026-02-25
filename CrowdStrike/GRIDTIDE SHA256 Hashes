// Known GRIDTIDE SHA256 Hashes 

#event_simpleName = /^(ProcessRollup2|PeFileWritten|SyntheticProcessRollup2)$/
| SHA256HashData = /^(ce36a5fc44cbd7de947130b67be9e732a7b4086fb1df98a5afd724087c973b47|01fc3bd5a78cd59255a867ffb3dfdd6e0b7713ee90098ea96cc01c640c6495eb|eb08c840f4c95e2fa5eff05e5f922f86c766f5368a63476f046b2b9dbffc2033|4eb994b816a1a24cf97bfd7551d00fe14b810859170dbf15180d39e05cd7c0f9|669917bad46a57e5f2de037f8ec200a44fb579d723af3e2f1be1e8479a267966)$/
| groupBy([ComputerName, UserName, ImageFileName, SHA256HashData, FileName],
    function=([count(aid, as=EventCount), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)]))
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| sort(LastSeen, order=desc)
