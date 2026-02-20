namespace NicoleGuard.Core.Scanning
{
    public class ScanResult
    {
        public string FilePath { get; set; } = string.Empty;
        public long FileSizeBytes { get; set; }
        public string SHA256Hash { get; set; } = string.Empty;
        public bool IsThreat { get; set; }
        public string ThreatType { get; set; } = string.Empty; // e.g., "Signature", "Heuristics"
        public string ThreatName { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public bool IsQuarantined { get; set; }
    }
}
