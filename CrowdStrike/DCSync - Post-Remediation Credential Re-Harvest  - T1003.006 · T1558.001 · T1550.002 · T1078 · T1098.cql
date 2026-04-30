// HUNT: DCSync — Post-Remediation Credential Re-Harvest
// Actor: Iranian MOIS-affiliated clusters
// Covers:  Mimikatz | Impacket | DRSUAPI | DSInternals
// MITRE:   T1003.006 | T1558.001 | T1550.002 | T1078

// STAGE 1: Fast index gate

"dcsync" OR "secretsdump" OR "drsuapi" OR "mimikatz"
OR "impacket" OR "ntds.dit" OR "ntdsutil" OR "Get-ADReplAccount"

// STAGE 2: Event source filter
   
| (#event_simpleName = "ProcessRollup2"
   OR #event_simpleName = "SyntheticProcessRollup2")

// STAGE 3: Field-level refinement
   
| (CommandLine = /(?i)(lsadump::dcsync|drsuapi|secretsdump|ntds\.dit|ntdsutil|mimikatz|mimilib|sekurlsa|impacket|Get-ADReplAccount)/
   OR ImageFileName = /(?i)(secretsdump|impacket)/)

// STAGE 4: Tier assignment
   
| case {
   
    // T1 — Direct protocol or module keyword
    CommandLine = /(?i)(lsadump::dcsync|drsuapi)/
      | Tier := "T1 — Direct DCSync/DRSUAPI";

    // T2 — Mimikatz with DCSync-mode targeting flags
    CommandLine = /(?i)(mimikatz|mimilib|sekurlsa)/
    AND CommandLine = /(?i)(\/domain:|\/dc:|lsadump|\/user:krbtgt|\/user:administrator|\/all)/
      | Tier := "T2 — Mimikatz DCSync Mode";

    // T3 — Impacket, NTDS, or DSInternals tooling
    (ImageFileName = /(?i)(secretsdump|impacket)/
     OR CommandLine = /(?i)(secretsdump\.py|impacket-secretsdump|ntds\.dit|ntdsutil|Get-ADReplAccount)/)
      | Tier := "T3 — Impacket/NTDS/DSInternals";

    // Catch-all: passed the index gate but no tier matched
    * | Tier := "T3 — Generic DCSync Keyword";
  }

//  STAGE 5: Binary name extraction 
| regex("(?i)(?:.*\\\\)?(?<BinaryName>[^\\\\]+\\.(?:exe|py|dll|ps1))$",
        field=ImageFileName, strict=false)

// STAGE 6: Sort then output 
| sort(@timestamp, order=desc)
| table(
    [@timestamp, Tier, ComputerName, UserName, BinaryName, 
     ImageFileName, CommandLine, ParentBaseFileName,
     ParentCommandLine, SHA256HashData, MD5HashData],
    limit=1000
  )
