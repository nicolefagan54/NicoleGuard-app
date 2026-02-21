using System.IO;
using System.Text.Json;

namespace NicoleGuard.Core.Services
{
    public class Settings
    {
        public string LastScanFolder { get; set; } = string.Empty;
        public string ThemeMode { get; set; } = "DarkTheme";
        public bool EnableBackgroundScan { get; set; } = true;
        public bool EnableActiveProtection { get; set; } = true;
        public string[] ExcludedExtensions { get; set; } = new[] { ".tmp", ".log", ".cache" };
        public string[] ExcludedFolders { get; set; } = new[] { ".git", "node_modules", "bin", "obj" };
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
