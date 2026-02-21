namespace NicoleGuard.Core.Models
{
    public class DetectionResult
    {
        public bool IsMalicious { get; set; }
        public string Reason { get; set; } = string.Empty;

        public static DetectionResult Clean() => new() { IsMalicious = false };
        public static DetectionResult Malicious(string reason) => new() { IsMalicious = true, Reason = reason };
    }
}
