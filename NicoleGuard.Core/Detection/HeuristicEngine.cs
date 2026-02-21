using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Detection
{
    public class HeuristicEngine
    {
        public DetectionResult Evaluate(string filePath)
        {
            var reasonList = new List<string>();
            var fileName = Path.GetFileName(filePath);
            var dir = Path.GetDirectoryName(filePath) ?? string.Empty;
            var ext = Path.GetExtension(filePath).ToLowerInvariant();

            int heuristicScore = 0;

            // Rule 1: EXE in Downloads
            if (ext == ".exe" && dir.ToLowerInvariant().Contains("downloads"))
            {
                reasonList.Add("Executable in Downloads");
                heuristicScore += 20;
            }

            // Rule 2: Double extension spoofing
            if (Regex.IsMatch(fileName, @"\.(txt|pdf|docx|jpg|png)\.exe$", RegexOptions.IgnoreCase))
            {
                reasonList.Add("Double extension (e.g., .pdf.exe)");
                heuristicScore += 50;
            }

            // Rule 3: Startup folder
            if (dir.ToLowerInvariant().Contains("startup"))
            {
                reasonList.Add("File in startup folder");
                heuristicScore += 60;
            }

            // Rule 4: Right-To-Left Override (RTLO) character spoofing 
            // The U+202E character reverses the text direction, commonly used to spoof extensions (e.g. gpj.exe -> exe.jpg)
            if (fileName.Contains('\u202E'))
            {
                reasonList.Add("RTLO Unicode Spoofing Detected");
                heuristicScore += 90;
            }

            // Rule 5: Suspiciously long file names
            if (fileName.Length > 100)
            {
                reasonList.Add("Excessively long filename");
                heuristicScore += 30;
            }

            // Optional: If heuristicScore breaches a specific threshold, we consider it actively malicious
            // Here we just flag anything with a score > 0 as suspicious, but you could tune this.
            if (heuristicScore == 0)
                return DetectionResult.Clean();

            return DetectionResult.Malicious($"Score {heuristicScore}: {string.Join("; ", reasonList)}");
        }
    }
}
