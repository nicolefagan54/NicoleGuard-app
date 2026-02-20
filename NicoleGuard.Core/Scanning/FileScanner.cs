using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace NicoleGuard.Core.Scanning
{
    public class FileScanner
    {
        public event EventHandler<ScanResult> FileScanned;
        public event EventHandler<string> ScanProgress;

        public List<ScanResult> ScanDirectory(string directoryPath, CancellationToken cancellationToken)
        {
            var results = new List<ScanResult>();
            if (!Directory.Exists(directoryPath))
            {
                return results;
            }

            try
            {
                var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    ScanProgress?.Invoke(this, $"Scanning: {file}");
                    var scanResult = ScanFile(file);
                    results.Add(scanResult);
                    FileScanned?.Invoke(this, scanResult);
                }
            }
            catch (UnauthorizedAccessException)
            {
                ScanProgress?.Invoke(this, $"Access denied: {directoryPath}");
            }
            catch (Exception ex)
            {
                ScanProgress?.Invoke(this, $"Error scanning directory: {ex.Message}");
            }

            return results;
        }

        public ScanResult ScanFile(string filePath)
        {
            var result = new ScanResult
            {
                FilePath = filePath
            };

            try
            {
                var fileInfo = new FileInfo(filePath);
                result.FileSizeBytes = fileInfo.Length;

                using (var sha256 = SHA256.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        var hashBytes = sha256.ComputeHash(stream);
                        result.SHA256Hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                    }
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }
    }
}
