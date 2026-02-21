using System;
using System.IO;
using NicoleGuard.Core.Detection;
using NicoleGuard.Core.Scanning;
using Xunit;

namespace NicoleGuard.Tests
{
    public class SignatureEngineTests : IDisposable
    {
        private string _tempDirPath;
        private string _badHashesFilePath;

        public SignatureEngineTests()
        {
            _tempDirPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirPath);
            _badHashesFilePath = Path.Combine(_tempDirPath, "bad_hashes.json");
        }

        [Fact]
        public void Analyze_NicoleTestFile_IsFlaggedAsThreat()
        {
            // Arrange
            var eicarPath = Path.Combine(_tempDirPath, "nicole_test_file.txt");
            var eicarString = @"NICOLEGUARD-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            File.WriteAllText(eicarPath, eicarString);
            
            // Generate exact hash of the file as written onto disk
            string computedHash;
            using (var stream = File.OpenRead(eicarPath))
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                var hashBytes = sha.ComputeHash(stream);
                var sb = new System.Text.StringBuilder();
                foreach (var b in hashBytes)
                    sb.Append(b.ToString("x2"));
                computedHash = sb.ToString();
            }

            var json = $@"{{ ""bad_hashes"": [ ""{computedHash}"" ] }}";
            File.WriteAllText(_badHashesFilePath, json);
            
            var signatureEngine = new SignatureEngine(_badHashesFilePath);
            var heuristicEngine = new HeuristicEngine();
            var scanner = new FileScanner(signatureEngine, heuristicEngine);

            // Act
            var scanResult = scanner.ScanFile(eicarPath);

            // Assert
            Assert.NotNull(scanResult);
            Assert.True(scanResult.IsMalicious);
            Assert.Contains("Signature match", scanResult.DetectionReason);
        }

        [Fact]
        public void Analyze_SafeFile_IsNotFlaggedAsThreat()
        {
            // Arrange
            var signatureEngine = new SignatureEngine(_badHashesFilePath);
            var heuristicEngine = new HeuristicEngine();
            var scanner = new FileScanner(signatureEngine, heuristicEngine);
            
            var safePath = Path.Combine(_tempDirPath, "safe_file.txt");
            File.WriteAllText(safePath, "Hello, world! I am a safe file.");

            // Act
            var scanResult = scanner.ScanFile(safePath);

            // Assert
            Assert.NotNull(scanResult);
            Assert.False(scanResult.IsMalicious);
        }

        public void Dispose()
        {
            if (Directory.Exists(_tempDirPath))
            {
                Directory.Delete(_tempDirPath, true);
            }
        }
    }
}
