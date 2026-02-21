using System.IO;
using System.Text.Json;

namespace NicoleGuard.Core.Services
{
    public class Settings
    {
        public string LastScanFolder { get; set; } = string.Empty;
    }

    public class SettingsService
    {
        private readonly string _settingsPath;
        public Settings Current { get; private set; } = new();

        public SettingsService(string baseDataFolder)
        {
            Directory.CreateDirectory(baseDataFolder);
            _settingsPath = Path.Combine(baseDataFolder, "settings.json");
            Load();
        }

        private void Load()
        {
            if (!File.Exists(_settingsPath))
            {
                Current = new Settings();
                Save();
                return;
            }

            var json = File.ReadAllText(_settingsPath);
            Current = JsonSerializer.Deserialize<Settings>(json) ?? new Settings();
        }

        public void Save()
        {
            var json = JsonSerializer.Serialize(Current, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_settingsPath, json);
        }
    }
}
