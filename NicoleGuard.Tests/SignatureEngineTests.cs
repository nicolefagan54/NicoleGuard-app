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

            // EICAR hash is: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
            _badHashesFilePath = Path.Combine(_tempDirPath, "bad_hashes.json");
            
            var json = @"{ ""bad_hashes"": [ ""275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"" ] }";
            File.WriteAllText(_badHashesFilePath, json);
        }

        [Fact]
        public void Analyze_EicarTestFile_IsFlaggedAsThreat()
        {
            // Arrange
            var scanner = new FileScanner();
            
            var eicarPath = Path.Combine(_tempDirPath, "nicole_test_file.txt");
            var eicarString = @"NICOLEGUARD-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            File.WriteAllText(eicarPath, eicarString);
            
            // Get actual computed hash to ensure we match it exactly
            var initialScanResult = scanner.ScanFile(eicarPath);
            Assert.True(string.IsNullOrEmpty(initialScanResult.ErrorMessage), $"Initial scan failed: {initialScanResult.ErrorMessage}");
            var actualHash = initialScanResult.SHA256Hash;
            Assert.False(string.IsNullOrEmpty(actualHash), "Computed hash is empty");
            
            // Write this specific hash to the bad_hashes file
            var json = $@"{{ ""bad_hashes"": [ ""{actualHash}"" ] }}";
            File.WriteAllText(_badHashesFilePath, json);
            
            var engine = new SignatureEngine(_badHashesFilePath);

            // Act
            var scanResult = scanner.ScanFile(eicarPath);
            Assert.True(string.IsNullOrEmpty(scanResult.ErrorMessage), $"Second scan failed: {scanResult.ErrorMessage}");
            bool isThreat = engine.Analyze(scanResult);

            // Assert
            Assert.True(isThreat, $"Failed to analyze as threat. Hash was {actualHash}, json file contents: {File.ReadAllText(_badHashesFilePath)}");
            Assert.True(scanResult.IsThreat);
            Assert.Equal("Signature", scanResult.ThreatType);
            Assert.Equal("Known Malicious Hash", scanResult.ThreatName);
        }

        [Fact]
        public void Analyze_SafeFile_IsNotFlaggedAsThreat()
        {
            // Arrange
            var engine = new SignatureEngine(_badHashesFilePath);
            var scanner = new FileScanner();
            
            var safePath = Path.Combine(_tempDirPath, "safe_file.txt");
            File.WriteAllText(safePath, "Hello, world! I am a safe file.");

            // Act
            var scanResult = scanner.ScanFile(safePath);
            bool isThreat = engine.Analyze(scanResult);

            // Assert
            Assert.False(isThreat);
            Assert.False(scanResult.IsThreat);
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
