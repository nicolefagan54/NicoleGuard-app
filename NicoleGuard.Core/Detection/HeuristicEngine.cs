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

            // Rule 1: EXE in Downloads
            if (ext == ".exe" && dir.ToLowerInvariant().Contains("downloads"))
                reasonList.Add("Executable in Downloads");

            // Rule 2: Double extension
            if (Regex.IsMatch(fileName, @"\.(txt|pdf|docx)\.exe$", RegexOptions.IgnoreCase))
                reasonList.Add("Double extension (e.g., .pdf.exe)");

            // Rule 3: Startup folder
            if (dir.ToLowerInvariant().Contains("startup"))
                reasonList.Add("File in startup folder");

            if (reasonList.Count == 0)
                return DetectionResult.Clean();

            return DetectionResult.Malicious(string.Join("; ", reasonList));
        }
    }
}
