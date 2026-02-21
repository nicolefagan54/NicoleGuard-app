using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Scanning
{
    public class FileScanner
    {
        private readonly Detection.SignatureEngine _signatureEngine;
        private readonly Detection.HeuristicEngine _heuristicEngine;

        public FileScanner(Detection.SignatureEngine signatureEngine,
                           Detection.HeuristicEngine heuristicEngine)
        {
            _signatureEngine = signatureEngine;
            _heuristicEngine = heuristicEngine;
        }

        public IEnumerable<ScanResult> ScanFolder(string folderPath)
        {
            var results = new List<ScanResult>();

            if (!Directory.Exists(folderPath))
                return results;

            foreach (var file in Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories))
            {
                ScanResult? result = ScanFile(file);
                if (result != null)
                    results.Add(result);
            }

            return results;
        }

        public ScanResult? ScanFile(string filePath)
        {
            try
            {
                string hash = ComputeSha256(filePath);

                var sigResult = _signatureEngine.CheckHash(hash);
                var heurResult = _heuristicEngine.Evaluate(filePath);

                bool isMalicious = sigResult.IsMalicious || heurResult.IsMalicious;
                string reason = string.Join(" | ",
                    new[] { sigResult.Reason, heurResult.Reason }
                    .Where(r => !string.IsNullOrWhiteSpace(r)));

                // Primitive gravity score logic based on detection engines
                int threatScore = 0;
                if (sigResult.IsMalicious) threatScore += 80;
                if (heurResult.IsMalicious) threatScore += 40;

                // Cap at 100
                threatScore = Math.Min(100, threatScore);

                // If they both failed but the file was flagged somehow
                if (isMalicious && threatScore == 0) threatScore = 50;

                return new ScanResult
                {
                    FilePath = filePath,
                    Hash = hash,
                    IsMalicious = isMalicious,
                    ThreatGravityScore = threatScore,
                    DetectionReason = reason
                };
            }
            catch
            {
                // Access denied, locked file, etc. – ignore for now or log.
                return null;
            }
        }

        private static string ComputeSha256(string filePath)
        {
            using var stream = File.OpenRead(filePath);
            using var sha = SHA256.Create();
            var hashBytes = sha.ComputeHash(stream);
            var sb = new StringBuilder();
            foreach (var b in hashBytes)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}
