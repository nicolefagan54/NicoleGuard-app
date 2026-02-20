using System;
using System.IO;
using NicoleGuard.Core.Scanning;

namespace NicoleGuard.Core.Detection
{
    public class HeuristicEngine
    {
        // Simple heuristic rules
        public bool Analyze(ScanResult result)
        {
            if (string.IsNullOrEmpty(result.FilePath)) return false;

            var fileName = Path.GetFileName(result.FilePath).ToLowerInvariant();
            var directoryInfo = new FileInfo(result.FilePath).Directory;
            var directoryName = directoryInfo?.Name.ToLowerInvariant() ?? "";
            
            // Rule 1: Double Extension (e.g., invoice.pdf.exe)
            if (fileName.EndsWith(".exe") && fileName.Contains(".pdf.exe"))
            {
                FlagAsThreat(result, "Double Extension Executable");
                return true;
            }

            // Rule 2: Executable in suspicious locations (e.g., Downloads/Temp folder running directly)
            if (fileName.EndsWith(".exe"))
            {
                string pathLower = result.FilePath.ToLowerInvariant();
                if (pathLower.Contains(@"\appdata\local\temp\") || 
                    (directoryName == "downloads" && result.FileSizeBytes > 0)) // Just an example, usually we'd want more complex logic here
                {
                    // In a real AV, an exe in downloads isn't always bad, but it might add 'points' to a score.
                    // For this simple example, we'll just flag if it matches a very specific pattern or score threshold.
                }
            }

            // Rule 3: Unusually large file claiming to be a script
            if ((fileName.EndsWith(".bat") || fileName.EndsWith(".vbs") || fileName.EndsWith(".ps1")) && result.FileSizeBytes > 10 * 1024 * 1024)
            {
                FlagAsThreat(result, "Suspiciously Large Script File");
                return true;
            }

            return false;
        }

        private void FlagAsThreat(ScanResult result, string threatName)
        {
            result.IsThreat = true;
            result.ThreatType = "Heuristic";
            result.ThreatName = threatName;
        }
    }
}
