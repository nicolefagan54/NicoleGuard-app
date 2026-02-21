using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Quarantine
{
    public class QuarantineManager
    {
        private readonly string _quarantineFolder;
        private readonly string _quarantineDbPath;
        private List<QuarantinedItem> _items = new();

        public QuarantineManager(string baseDataFolder)
        {
            _quarantineFolder = Path.Combine(baseDataFolder, "Quarantine");
            Directory.CreateDirectory(_quarantineFolder);

            _quarantineDbPath = Path.Combine(baseDataFolder, "quarantine.json");
            Load();
        }

        public IReadOnlyList<QuarantinedItem> Items => _items;

        public QuarantinedItem? QuarantineFile(string filePath, string reason)
        {
            if (!File.Exists(filePath))
                return null;

            var fileName = Path.GetFileName(filePath);
            var destPath = Path.Combine(_quarantineFolder, $"{Guid.NewGuid()}_{fileName}");

            File.Move(filePath, destPath);

            var item = new QuarantinedItem
            {
                OriginalPath = filePath,
                QuarantinePath = destPath,
                Reason = reason
            };

            _items.Add(item);
            Save();
            return item;
        }

        public bool Restore(string id)
        {
            var item = _items.FirstOrDefault(i => i.Id == id);
            if (item == null || !File.Exists(item.QuarantinePath))
                return false;

            Directory.CreateDirectory(Path.GetDirectoryName(item.OriginalPath)!);
            File.Move(item.QuarantinePath, item.OriginalPath, overwrite: true);
            _items.Remove(item);
            Save();
            return true;
        }

        public bool Delete(string id)
        {
            var item = _items.FirstOrDefault(i => i.Id == id);
            if (item == null)
                return false;

            if (File.Exists(item.QuarantinePath))
                File.Delete(item.QuarantinePath);

            _items.Remove(item);
            Save();
            return true;
        }

        private void Load()
        {
            if (!File.Exists(_quarantineDbPath))
            {
                _items = new List<QuarantinedItem>();
                return;
            }

            var json = File.ReadAllText(_quarantineDbPath);
            _items = JsonSerializer.Deserialize<List<QuarantinedItem>>(json) ?? new List<QuarantinedItem>();
        }

        private void Save()
        {
            var json = JsonSerializer.Serialize(_items, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_quarantineDbPath, json);
        }
    }
}
