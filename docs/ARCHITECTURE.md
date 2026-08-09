# Architecture

The Windows service runs a message-only native window and registers for all
device-interface classes with `RegisterDeviceNotificationW`. Its window
procedure turns `WM_DEVICECHANGE` messages into owned Rust values immediately;
no borrowed Windows pointers cross the callback boundary.

A channel separates native collection from policy and persistence. The service
applies local vendor/product rules, reports notices and alerts through Windows
Event Log, appends the event transactionally to bundled SQLite, and verifies the
complete chain after each write. The service accepts stop and shutdown controls
and terminates the notification thread with a thread message.

The domain, policy, hash chain, SQLite adapter, and JSON/CSV exporters are
testable without installing a service. Native code is gated to Windows and CI
runs on a Windows host.
