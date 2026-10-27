// Title:      Executable Persistence via Run Key from ProgramData
// Rationale:   Flags Run-key values whose data launches an .exe from C:\ProgramData: the
//              persistence pattern CloudSEK reported for MuddyWater's RustyWater implant,
//              generalised to any ProgramData executable.
// MITRE ATT&CK: T1547.001 — Registry Run Keys / Startup Folder
// Ref:           https://www.cloudsek.com/blog/reborn-in-rust-muddywater-evolves-tooling-with-rustywater-implant
// Rustywater Muddywater Rust based evolution
| "#event_simpleName" = RegistryOperationDetectInfo
| registry.key = "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| RegStringValue = "*C:\\ProgramData\\*" AND RegStringValue = "*.exe"
// | RegValueName != LenovoVantageToolbar
| table([ComputerName, FileName, FilePath, registry.key, registry.value, RegValueName, CommandLine])
