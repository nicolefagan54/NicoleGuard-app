using Microsoft.Win32;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using NicoleGuard.Core.Detection;
using NicoleGuard.Core.Models;
using NicoleGuard.Core.Quarantine;
using NicoleGuard.Core.Scanning;
using NicoleGuard.Core.Services;

namespace NicoleGuard.UI
{
    public partial class MainWindow : Window
    {
        private readonly FileScanner _scanner;
        private readonly QuarantineManager _quarantineManager;
        private readonly SettingsService _settings;
        private readonly LogService _log;
        private readonly PresetScanService _presetScan;
        private readonly BackgroundScanService _backgroundScan;
        private readonly SignatureUpdateService _updateService;
        private readonly string _dataFolder;
        private readonly ObservableCollection<ScanResult> _results = new();

        private string _currentFolder = string.Empty;

        public MainWindow()
        {
            InitializeComponent();

            _dataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "NicoleGuard");

            Directory.CreateDirectory(_dataFolder);

            string badHashesPath = Path.Combine(_dataFolder, "bad_hashes.json");
            if (!File.Exists(badHashesPath))
            {
                // Create a default file with a sample hash (the provided EICAR string hash)
                var json = @"{ ""bad_hashes"": [ ""c4d2b335c80cb7a7043031d60d5334e66b7df8d44a28b5291afdd0ada79ac393"" ] }";
                File.WriteAllText(badHashesPath, json);
            }

            var signatureEngine = new SignatureEngine(badHashesPath);
            var heuristicEngine = new HeuristicEngine();
            _scanner = new FileScanner(signatureEngine, heuristicEngine);
            _presetScan = new PresetScanService(_scanner);
            _quarantineManager = new QuarantineManager(_dataFolder);
            _settings = new SettingsService(_dataFolder);
            _log = new LogService(_dataFolder);
            _updateService = new SignatureUpdateService(_dataFolder, _log);

            _currentFolder = _settings.Current.LastScanFolder;
            GridResults.ItemsSource = _results;

            _backgroundScan = new BackgroundScanService(_scanner, _log, intervalMinutes: 10);
            _backgroundScan.OnThreatFound += BackgroundScan_OnThreatFound;

            if (_settings.Current.EnableBackgroundScan)
            {
                _backgroundScan.Start();
            }

            // Apply saved theme
            ((App)System.Windows.Application.Current).ApplyTheme(_settings.Current.ThemeMode);
            CboTheme.Text = _settings.Current.ThemeMode;
        }

        private void BtnChooseFolder_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new System.Windows.Forms.FolderBrowserDialog();
            var result = dlg.ShowDialog();
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                _currentFolder = dlg.SelectedPath;
                _settings.Current.LastScanFolder = _currentFolder;
                _settings.Save();
                TxtStatus.Text = $"Selected: {_currentFolder}";
            }
        }

        private async void BtnShieldScan_Click(object sender, RoutedEventArgs e)
        {
            TxtStatus.Text = "Running Gravity Shield scan (Downloads, Desktop, Startup, Temp)...";
            _results.Clear();

            await Task.Run(() =>
            {
                var scanResults = _presetScan.RunShieldScan();
                Dispatcher.Invoke(() =>
                {
                    foreach (var r in scanResults)
                        _results.Add(r);
                });
            });

            TxtStatus.Text = $"🛡️ Shield Scan complete. {_results.Count} files scanned.";
            _log.Info($"Shield Scan completed, files: {_results.Count}");
        }

        private async void BtnScan_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_currentFolder))
            {
                System.Windows.MessageBox.Show("Please choose a folder first.");
                return;
            }

            TxtStatus.Text = "Scanning...";
            _results.Clear();

            await Task.Run(() =>
            {
                var scanResults = _scanner.ScanFolder(_currentFolder);
                Dispatcher.Invoke(() =>
                {
                    foreach (var r in scanResults)
                        _results.Add(r);
                });
            });

            TxtStatus.Text = $"Scan complete. {_results.Count} files scanned.";
            _log.Info($"Scan completed for folder: {_currentFolder}, files: {_results.Count}");
        }

        private void BtnQuarantineSelected_Click(object sender, RoutedEventArgs e)
        {
            var selected = GridResults.SelectedItems.Cast<ScanResult>().ToList();
            if (!selected.Any())
            {
                System.Windows.MessageBox.Show("Select at least one file to quarantine.");
                return;
            }

            foreach (var item in selected.Where(i => i.IsMalicious))
            {
                var q = _quarantineManager.QuarantineFile(item.FilePath, item.DetectionReason);
                if (q != null)
                    _log.Info($"Quarantined: {q.OriginalPath} -> {q.QuarantinePath} ({q.Reason})");
            }

            System.Windows.MessageBox.Show("Selected malicious files quarantined (if still present).");
        }

        private async void BtnUpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            TxtStatus.Text = "Updating Threat Signatures from Cloud...";
            bool success = await _updateService.UpdateSignaturesAsync();

            if (success)
            {
                // Reinstantiate the scanner elements using the updated file
                var signatureEngine = new SignatureEngine(Path.Combine(_dataFolder, "bad_hashes.json"));
                var heuristicEngine = new HeuristicEngine();
                
                // We must use reflection or a property injection to swap the engines,
                // but for this simple architecture, we will just rebuild the scanner entirely.
                var newScanner = new FileScanner(signatureEngine, heuristicEngine);
                
                // Swap the reference in MainWindow
                var scannerField = this.GetType().GetField("_scanner", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (scannerField != null)
                {
                    scannerField.SetValue(this, newScanner);
                }

                // Swap the reference in the Shield Scan service
                var presetField = this.GetType().GetField("_presetScan", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (presetField != null)
                {
                    presetField.SetValue(this, new PresetScanService(newScanner));
                }

                TxtStatus.Text = "Signatures successfully updated and reloaded.";
                System.Windows.MessageBox.Show("Threat definitions have been updated from the cloud.", "Update Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                TxtStatus.Text = "Failed to update signatures. Check logs.";
                System.Windows.MessageBox.Show("Failed to download signature updates.", "Update Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnQuarantineWindow_Click(object sender, RoutedEventArgs e)
        {
            var win = new Views.QuarantineWindow(_quarantineManager);
            win.ShowDialog();
        }

        private void CboTheme_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (CboTheme.SelectedItem is System.Windows.Controls.ComboBoxItem item)
            {
                var theme = item.Content.ToString();
                if (theme != null)
                {
                    ((App)System.Windows.Application.Current).ApplyTheme(theme);
                    _settings.Current.ThemeMode = theme;
                    _settings.Save();
                }
            }
        }

        private void BackgroundScan_OnThreatFound(object? sender, string message)
        {
            // The timer runs on a background thread, so we must marshal the MessageBox popup back to the UI thread
            Dispatcher.Invoke(() =>
            {
                System.Windows.MessageBox.Show(message, "Antigravity Active Shield Alert", MessageBoxButton.OK, MessageBoxImage.Warning);
            });
        }
    }
}