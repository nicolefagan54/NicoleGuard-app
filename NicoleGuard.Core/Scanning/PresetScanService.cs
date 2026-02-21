using System;
using System.Collections.Generic;
using System.IO;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Scanning
{
    public class PresetScanService
    {
        private readonly FileScanner _scanner;

        public PresetScanService(FileScanner scanner)
        {
            _scanner = scanner;
        }

        public IEnumerable<ScanResult> RunShieldScan()
        {
            var folders = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Path.GetTempPath()
            };

            var allResults = new List<ScanResult>();
            foreach (var folder in folders)
            {
                if (Directory.Exists(folder))
                {
                    allResults.AddRange(_scanner.ScanFolder(folder));
                }
            }
            return allResults;
        }
    }
}
