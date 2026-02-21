using Microsoft.ML.Data;

namespace NicoleGuard.Core.MachineLearning
{
    public class FileFeatures
    {
        [LoadColumn(0)]
        public float FileSizeMB { get; set; }

        [LoadColumn(1)]
        public float Entropy { get; set; }

        [LoadColumn(2)]
        public float IsExecutable { get; set; }

        [LoadColumn(3)]
        public float ContainsHiddenAttributes { get; set; }

        [LoadColumn(4)]
        public bool IsMalicious { get; set; }
    }
}
