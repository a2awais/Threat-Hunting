// Intel: https://www.cloudsek.com/blog/reborn-in-rust-muddywater-evolves-tooling-with-rustywater-implant
// Rustywater Muddywater Rust based evolution
| "#event_simpleName" = RegistryOperationDetectInfo
| registry.key = "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| RegStringValue = "*C:\\ProgramData\\*" AND RegStringValue = "*.exe"
// | RegValueName != LenovoVantageToolbar
| table([ComputerName, FileName, FilePath, registry.key, registry.value, RegValueName, CommandLine])
