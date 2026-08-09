# Operations

Use a dedicated service identity with write access only to its data directory.
Grant read access to exports deliberately. Back up the SQLite database together
with its WAL files or use SQLite's online backup facilities.

Before relying on alerts:

1. inventory expected devices;
2. define narrow `VID:PID` rules and test them with synthetic events;
3. verify Windows Event Log collection and forwarding;
4. test arrival and removal on representative hardware;
5. document retention and incident-response ownership.

Run `export-json` or `export-csv` only after the chain verifies. The command
refuses export when chain verification fails.
