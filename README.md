# Peripheral Ledger

Peripheral Ledger is a Windows service that records native device-interface
arrival, removal, and topology notifications in SQLite. Every row links to the
previous row with SHA-256, local vendor/product rules can raise explainable
alerts, notices are also sent to Windows Event Log, and verified histories can
be exported as JSON or CSV.

```powershell
cargo run -- demo
cargo test --all-targets
cargo run -- export-json C:\ProgramData\PeripheralLedger\events.db
cargo run -- export-csv C:\ProgramData\PeripheralLedger\events.db
```

## Install the service

Build the release executable, then use an elevated terminal to register it with
the Service Control Manager. Review the exact path before running the command.

```powershell
cargo build --release
sc.exe create PeripheralLedger binPath= "E:\PeripheralLedger\target\release\peripheral-ledger.exe service" start= auto
sc.exe start PeripheralLedger
```

The service stores its database at
`C:\ProgramData\PeripheralLedger\events.db`. Optional alert pairs are read from
`PERIPHERAL_LEDGER_DENY` as comma-separated `VID:PID` values. Service environment
configuration should be set at the service boundary, not committed here.

Device interface paths may include serial-like identifiers. Keep the database
and exports access-controlled, disclose collection to affected users, and set a
retention policy. The hash chain is tamper-evident, not a digital signature or
proof that the host itself was uncompromised.

See [Architecture](docs/ARCHITECTURE.md), [Operations](docs/OPERATIONS.md), and
[Clean-room boundary](docs/CLEAN_ROOM_BOUNDARY.md).
