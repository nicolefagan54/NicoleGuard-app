using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using NicoleGuard.Core.Scanning;

namespace NicoleGuard.Core.Services
{
    public class ActiveMonitorService : IDisposable
    {
        private readonly FileScanner _scanner;
        private readonly LogService _log;
        private FileSystemWatcher? _downloadsWatcher;
        private FileSystemWatcher? _desktopWatcher;
        private readonly ConcurrentQueue<string> _scanQueue = new();
        private bool _isProcessingQueue = false;

        public event EventHandler<string>? OnThreatIntercepted;

        public ActiveMonitorService(FileScanner scanner, LogService log)
        {
            _scanner = scanner;
            _log = log;
        }

        public void StartMonitoring()
        {
            try
            {
                string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

                _downloadsWatcher = SetupWatcher(downloadsPath);
                _desktopWatcher = SetupWatcher(desktopPath);

                _log.Info("ActiveMonitorService: FileSystemWatchers engaged for Downloads and Desktop.");
            }
            catch (Exception ex)
            {
                _log.Error($"ActiveMonitorService Failed to Start: {ex.Message}");
            }
        }

        public void StopMonitoring()
        {
            if (_downloadsWatcher != null) _downloadsWatcher.EnableRaisingEvents = false;
            _downloadsWatcher?.Dispose();

            if (_desktopWatcher != null) _desktopWatcher.EnableRaisingEvents = false;
            _desktopWatcher?.Dispose();

            _log.Info("ActiveMonitorService: FileSystemWatchers disengaged.");
        }

        private FileSystemWatcher SetupWatcher(string path)
        {
            if (!Directory.Exists(path)) return null!;

            var watcher = new FileSystemWatcher(path);
            watcher.IncludeSubdirectories = true;

            // Only watch for new files or renamed files
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime;
            
            watcher.Created += OnFileEvent;
            watcher.Renamed += OnFileEvent;

            watcher.EnableRaisingEvents = true;
            return watcher;
        }

        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            // Ignore temporary downloads or partial files (like .crdownload from Chrome)
            if (e.FullPath.EndsWith(".crdownload") || e.FullPath.EndsWith(".tmp"))
                return;

            _scanQueue.Enqueue(e.FullPath);
            ProcessQueueAsync();
        }

        private async void ProcessQueueAsync()
        {
            if (_isProcessingQueue) return;
            _isProcessingQueue = true;

            await Task.Run(async () =>
            {
                while (_scanQueue.TryDequeue(out string? filePath))
                {
                    if (string.IsNullOrEmpty(filePath)) continue;

                    try
                    {
                        // Wait briefly to ensure the file lock is released by the downloader
                        await Task.Delay(500);

                        if (!File.Exists(filePath)) continue;

                        _log.Info($"ActiveMonitor intercepted: {filePath}");
                        var result = _scanner.ScanFile(filePath);

                        if (result != null && result.IsMalicious)
                        {
                            string msg = $"Active Protection Intercepted a Threat!\n\nFile: {result.FilePath}\nReason: {result.DetectionReason}\nGravity Score: {result.ThreatGravityScore}";
                            _log.Error(msg);
                            OnThreatIntercepted?.Invoke(this, msg);
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Error($"Failed to active scan {filePath}: {ex.Message}");
                    }
                }

                _isProcessingQueue = false;
            });
        }

        public void Dispose()
        {
            StopMonitoring();
        }
    }
}
