using System;
using System.IO;

namespace NicoleGuard.Core.MachineLearning
{
    public static class FeatureExtractor
    {
        public static FileFeatures ExtractFeatures(string filePath)
        {
            var features = new FileFeatures
            {
                IsMalicious = false // Default during extraction, evaluated later
            };

            try
            {
                var fileInfo = new FileInfo(filePath);
                features.FileSizeMB = (float)(fileInfo.Length / 1024f / 1024f);

                string ext = fileInfo.Extension.ToLower();
                features.IsExecutable = (ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".ps1" || ext == ".scr") ? 1f : 0f;

                features.ContainsHiddenAttributes = fileInfo.Attributes.HasFlag(FileAttributes.Hidden) ? 1f : 0f;

                // Calculate Shannon Entropy
                features.Entropy = CalculateEntropy(filePath);
            }
            catch
            {
                // Unreadable files could be suspicious or simply locked
                features.Entropy = 0f;
            }

            return features;
        }

        private static float CalculateEntropy(string filePath)
        {
            // Shannon Entropy calculates the randomness/density of a file.
            // High entropy (> 7.0) often indicates packed or encrypted malware.
            
            // To prevent large files from hogging memory/CPU during entropy calculation,
            // we will sample up to the first 4MB of the file.
            const int maxBytesToRead = 4 * 1024 * 1024;
            
            byte[] buffer = new byte[8192];
            int[] frequencies = new int[256];
            long totalBytesRead = 0;

            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                int bytesRead;
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0 && totalBytesRead < maxBytesToRead)
                {
                    totalBytesRead += bytesRead;
                    for (int i = 0; i < bytesRead; i++)
                    {
                        frequencies[buffer[i]]++;
                    }
                }
            }

            if (totalBytesRead == 0) return 0f;

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double probability = (double)frequencies[i] / totalBytesRead;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return (float)entropy;
        }
    }
}
