using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using NicoleGuard.Core.Scanning;

namespace NicoleGuard.Core.Detection
{
    public class SignatureEngine
    {
        private readonly HashSet<string> _knownBadHashes;

        public SignatureEngine(string hashDatabaseFilePath)
        {
            _knownBadHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            LoadHashes(hashDatabaseFilePath);
        }

        private void LoadHashes(string filePath)
        {
            if (File.Exists(filePath))
            {
                try
                {
                    var json = File.ReadAllText(filePath);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("bad_hashes", out var array))
                    {
                        foreach (var item in array.EnumerateArray())
                        {
                            var hash = item.GetString();
                            if (!string.IsNullOrEmpty(hash))
                            {
                                _knownBadHashes.Add(hash);
                            }
                        }
                    }
                }
                catch
                {
                    // Ignore load errors for this simple version
                }
            }
        }

        public bool Analyze(ScanResult result)
        {
            if (string.IsNullOrEmpty(result.SHA256Hash))
                return false;

            if (_knownBadHashes.Contains(result.SHA256Hash))
            {
                result.IsThreat = true;
                result.ThreatType = "Signature";
                result.ThreatName = "Known Malicious Hash";
                return true;
            }

            return false;
        }
    }
}
