using System;

namespace NicoleGuard.Core.Models
{
    public class QuarantinedItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string OriginalPath { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime QuarantinedAt { get; set; } = DateTime.UtcNow;
    }
}
