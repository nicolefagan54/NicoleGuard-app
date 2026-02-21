namespace NicoleGuard.Core.Models
{
    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string SignatureStatus { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public double MemoryUsageMB { get; set; }
    }
}
