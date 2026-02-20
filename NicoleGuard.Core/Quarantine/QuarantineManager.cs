using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace NicoleGuard.Core.Quarantine
{
    public class QuarantinedFile
    {
        public string OriginalPath { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public DateTime QuarantinedAt { get; set; }
        public string ThreatName { get; set; } = string.Empty;
    }

    public class QuarantineManager
    {
        private readonly string _quarantineDirectory;
        private readonly string _metaDataPath;
        private List<QuarantinedFile> _quarantinedFiles;

        public QuarantineManager(string dataDirectory)
        {
            _quarantineDirectory = Path.Combine(dataDirectory, "QuarantineFiles");
            _metaDataPath = Path.Combine(dataDirectory, "quarantine.json");
            _quarantinedFiles = new List<QuarantinedFile>();

            if (!Directory.Exists(_quarantineDirectory))
            {
                Directory.CreateDirectory(_quarantineDirectory);
            }

            LoadMetadata();
        }

        private void LoadMetadata()
        {
            if (File.Exists(_metaDataPath))
            {
                try
                {
                    var json = File.ReadAllText(_metaDataPath);
                    _quarantinedFiles = JsonSerializer.Deserialize<List<QuarantinedFile>>(json) ?? new List<QuarantinedFile>();
                }
                catch
                {
                    _quarantinedFiles = new List<QuarantinedFile>();
                }
            }
        }

        private void SaveMetadata()
        {
            try
            {
                var json = JsonSerializer.Serialize(_quarantinedFiles, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_metaDataPath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving quarantine metadata: {ex.Message}");
            }
        }

        public bool Quarantine(string originalFilePath, string threatName)
        {
            if (!File.Exists(originalFilePath)) return false;

            try
            {
                var safeFileName = Guid.NewGuid().ToString() + ".qtz";
                var quarantinePath = Path.Combine(_quarantineDirectory, safeFileName);

                File.Move(originalFilePath, quarantinePath);

                var record = new QuarantinedFile
                {
                    OriginalPath = originalFilePath,
                    QuarantinePath = quarantinePath,
                    QuarantinedAt = DateTime.Now,
                    ThreatName = threatName
                };

                _quarantinedFiles.Add(record);
                SaveMetadata();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public List<QuarantinedFile> GetQuarantinedFiles() => _quarantinedFiles;

        public bool Restore(QuarantinedFile fileRecord)
        {
            if (!File.Exists(fileRecord.QuarantinePath)) return false;

            try
            {
                var directory = Path.GetDirectoryName(fileRecord.OriginalPath);
                if (directory != null && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                File.Move(fileRecord.QuarantinePath, fileRecord.OriginalPath);
                _quarantinedFiles.Remove(fileRecord);
                SaveMetadata();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Delete(QuarantinedFile fileRecord)
        {
            if (File.Exists(fileRecord.QuarantinePath))
            {
                try
                {
                    File.Delete(fileRecord.QuarantinePath);
                    _quarantinedFiles.Remove(fileRecord);
                    SaveMetadata();
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            return false;
        }
    }
}
