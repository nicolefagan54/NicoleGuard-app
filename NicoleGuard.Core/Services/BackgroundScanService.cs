using System;
using System.IO;
using System.Linq;
using System.Timers;
using NicoleGuard.Core.Detection;
using NicoleGuard.Core.Scanning;

namespace NicoleGuard.Core.Services
{
    public class BackgroundScanService
    {
        private readonly FileScanner _scanner;
        private readonly System.Timers.Timer _timer;
        private readonly LogService _log;

        // Will fire if malicious files are found
        public event EventHandler<string>? OnThreatFound;

        private readonly string[] _monitorFolders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.GetTempPath()
        };

        public BackgroundScanService(FileScanner scanner, LogService log, int intervalMinutes = 10)
        {
            _scanner = scanner;
            _log = log;

            // Convert minutes to ms
            _timer = new System.Timers.Timer(intervalMinutes * 60 * 1000);
            _timer.Elapsed += ExecuteScan;
        }

        public void Start()
        {
            _log.Info("BackgroundScanService started.");
            _timer.Start();
            
            // Execute an immediate scan on startup instead of waiting for the first tick
            ExecuteScan(null, null);
        }

        public void Stop()
        {
            _log.Info("BackgroundScanService stopped.");
            _timer.Stop();
        }

        private void ExecuteScan(object? sender, ElapsedEventArgs? e)
        {
            _log.Info("Running scheduled background scan...");

            foreach (var folder in _monitorFolders)
            {
                if (!Directory.Exists(folder)) continue;

                var results = _scanner.ScanFolder(folder);
                var malicious = results.Where(r => r.IsMalicious).ToList();

                if (malicious.Any())
                {
                    _log.Error($"Background scan found {malicious.Count} threats in {folder}.");
                    var threatNames = string.Join("\n", malicious.Select(m => m.FilePath));
                    
                    // Alert the UI thread
                    OnThreatFound?.Invoke(this, $"WARNING: {malicious.Count} threats were automatically detected!\n\n{threatNames}");
                }
            }
        }
    }
}
