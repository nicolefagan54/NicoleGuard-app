using System;
using System.IO;

namespace NicoleGuard.Core.Services
{
    public class LogService
    {
        private readonly string _logPath;

        public LogService(string baseDataFolder)
        {
            Directory.CreateDirectory(baseDataFolder);
            _logPath = Path.Combine(baseDataFolder, "nicoleguard.log");
        }

        public void Info(string message) => Write("INFO", message);
        public void Error(string message) => Write("ERROR", message);

        private void Write(string level, string message)
        {
            var line = $"{DateTime.UtcNow:O} [{level}] {message}";
            File.AppendAllLines(_logPath, new[] { line });
        }
    }
}
