namespace NicoleGuard.Core.Models
{
    public class ScanResult
    {
        public string FilePath { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
        public bool IsMalicious { get; set; }
        public int ThreatGravityScore { get; set; }
        public string DetectionReason { get; set; } = string.Empty;
    }
}
