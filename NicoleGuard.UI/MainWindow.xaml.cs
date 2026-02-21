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
        private readonly ObservableCollection<ScanResult> _results = new();

        private string _currentFolder = string.Empty;

        public MainWindow()
        {
            InitializeComponent();

            string dataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "NicoleGuard");

            var signatureEngine = new SignatureEngine(Path.Combine(dataFolder, "bad_hashes.json"));
            var heuristicEngine = new HeuristicEngine();
            _scanner = new FileScanner(signatureEngine, heuristicEngine);
            _quarantineManager = new QuarantineManager(dataFolder);
            _settings = new SettingsService(dataFolder);
            _log = new LogService(dataFolder);

            _currentFolder = _settings.Current.LastScanFolder;
            GridResults.ItemsSource = _results;
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

        private void BtnQuarantineWindow_Click(object sender, RoutedEventArgs e)
        {
            var win = new Views.QuarantineWindow(_quarantineManager);
            win.ShowDialog();
        }
    }
}