using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Scanning
{
    public class StartupScanner
    {
        private readonly FileScanner _scanner;
        private readonly Services.LogService _log;

        public StartupScanner(FileScanner scanner, Services.LogService log)
        {
            _scanner = scanner;
            _log = log;
        }

        public IEnumerable<ScanResult> ScanStartupLocations()
        {
            var results = new List<ScanResult>();

            // 1. Scan Startup Folder
            string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(startupFolder))
            {
                results.AddRange(_scanner.ScanFolder(startupFolder));
            }

            // 2. Scan Registry Run Keys (HKCU)
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: false);
                if (key != null)
                {
                    foreach (string valueName in key.GetValueNames())
                    {
                        string? path = key.GetValue(valueName) as string;
                        if (!string.IsNullOrWhiteSpace(path))
                        {
                            // Registry paths can be messy, wrapped in quotes, or have arguments.
                            // We do a basic cleanup to try and extract the actual executable path.
                            string cleanPath = path.Replace("\"", "").Split(new[] { ".exe " }, StringSplitOptions.None)[0];
                            if (!cleanPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                cleanPath += ".exe";

                            if (File.Exists(cleanPath))
                            {
                                var result = _scanner.ScanFile(cleanPath);
                                if (result != null)
                                    results.Add(result);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Error($"Failed to read HKCU Run key: {ex.Message}");
            }

            return results;
        }
    }
}
