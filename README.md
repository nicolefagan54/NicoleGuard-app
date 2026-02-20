# NicoleGuard-app

NicoleGuard is a personal Windows security scanner built with C# and WPF.

## Features
- **File Scanner**: Recursively scans directories and computes SHA-256 hashes.
- **Signature Detection**: Identifies known malicious hashes from a database (`bad_hashes.json`).
- **Heuristic Detection**: Flags suspicious files based on heuristics (e.g., location, double extensions).
- **Quarantine Manager**: Safely isolates detected threats to a secure directory.

## Project Structure
- `NicoleGuard.UI`: WPF Application dashboard
- `NicoleGuard.Core`: Scanning and detection logic
- `NicoleGuard.Data`: Threat database storage
