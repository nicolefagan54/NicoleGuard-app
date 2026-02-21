using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Detection
{
    public class SignatureEngine
    {
        private readonly HashSet<string> _badHashes = new();

        public SignatureEngine(string badHashesPath)
        {
            if (File.Exists(badHashesPath))
            {
                var json = File.ReadAllText(badHashesPath);
                var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("bad_hashes", out var arr))
                {
                    foreach (var el in arr.EnumerateArray())
                    {
                        var h = el.GetString();
                        if (!string.IsNullOrWhiteSpace(h))
                            _badHashes.Add(h.ToLowerInvariant());
                    }
                }
            }
        }

        public DetectionResult CheckHash(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return DetectionResult.Clean();

            if (_badHashes.Contains(hash.ToLowerInvariant()))
                return DetectionResult.Malicious("Signature match");

            return DetectionResult.Clean();
        }
    }
}
