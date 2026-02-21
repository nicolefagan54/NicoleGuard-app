# NicoleGuard-app

NicoleGuard is a personal Windows security scanner built with C# and WPF.

## Features

- **File Scanner**: Recursively scans directories and computes SHA-256 hashes.
- **Signature Detection**: Identifies known malicious hashes from a database (`bad_hashes.json`).
- **Heuristic Detection**: Flags suspicious files based on heuristics (e.g., location, double extensions).
- **Quarantine Manager**: Safely isolates detected threats to a secure directory.

## Architecture

NicoleGuard is split into two main projects:

- `NicoleGuard.Core` – scanning, detection, quarantine, settings, logging
- `NicoleGuard.UI` – WPF desktop interface

### Data flow

1. The user selects a folder and starts a scan in the WPF UI.
2. `MainWindow` calls `FileScanner` from `NicoleGuard.Core`.
3. `FileScanner`:
   - Walks the folder
   - Computes SHA-256 hashes
   - Sends hashes to `SignatureEngine`
   - Sends file paths to `HeuristicEngine`
4. The combined result is shown in the UI as a list of `ScanResult` items.
5. When the user quarantines a file:
   - `MainWindow` calls `QuarantineManager`
   - The file is moved to the Quarantine folder
   - Metadata is stored in `quarantine.json`
6. `QuarantineWindow` lets the user restore or delete quarantined items.
7. `SettingsService` and `LogService` manage `settings.json` and `nicoleguard.log`.

### Storage

- `%AppData%/NicoleGuard/bad_hashes.json` – known malicious hashes
- `%AppData%/NicoleGuard/quarantine.json` – quarantined items
- `%AppData%/NicoleGuard/settings.json` – last scan folder, etc.
- `%AppData%/NicoleGuard/nicoleguard.log` – basic log file
