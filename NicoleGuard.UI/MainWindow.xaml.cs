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
        private readonly ActiveMonitorService _activeMonitor;
        private readonly StartupScanner _startupScanner;
        private readonly SignatureUpdateService _updateService;
        private readonly string _dataFolder;
        private readonly ObservableCollection<ScanResult> _results = new();
        private System.Windows.Media.Animation.Storyboard? _pulseStoryboard;

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

            _settings = new SettingsService(_dataFolder);

            _log = new LogService(_dataFolder);

            var signatureEngine = new SignatureEngine(badHashesPath);
            var heuristicEngine = new HeuristicEngine();
            _scanner = new FileScanner(signatureEngine, heuristicEngine, _settings);
            _presetScan = new PresetScanService(_scanner);
            _startupScanner = new StartupScanner(_scanner, _log);
            _quarantineManager = new QuarantineManager(_dataFolder);
            _updateService = new SignatureUpdateService(_dataFolder, _log);

            _currentFolder = _settings.Current.LastScanFolder;
            GridResults.ItemsSource = _results;

            _backgroundScan = new BackgroundScanService(_scanner, _log, intervalMinutes: 10);
            _backgroundScan.OnThreatFound += BackgroundScan_OnThreatFound;

            if (_settings.Current.EnableBackgroundScan)
            {
                _backgroundScan.Start();
            }

            _activeMonitor = new ActiveMonitorService(_scanner, _log);
            _activeMonitor.OnThreatIntercepted += ActiveMonitor_OnThreatIntercepted;

            if (_settings.Current.EnableActiveProtection)
            {
                _activeMonitor.StartMonitoring();
                ChkActiveProtection.IsChecked = true;
            }
            else
            {
                ChkActiveProtection.IsChecked = false;
            }

            // Apply saved theme
            ((App)System.Windows.Application.Current).ApplyTheme(_settings.Current.ThemeMode);
            CboTheme.Text = _settings.Current.ThemeMode;

            CreatePulseAnimation();

            TxtStatus.Text = "NicoleGuard is Ready!";
            _log.Info("Application started successfully.");
        }

        private void CreatePulseAnimation()
        {
            _pulseStoryboard = new System.Windows.Media.Animation.Storyboard();
            _pulseStoryboard.RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever;

            var scaleX = new System.Windows.Media.Animation.DoubleAnimation(1, 4, TimeSpan.FromSeconds(1));
            var scaleY = new System.Windows.Media.Animation.DoubleAnimation(1, 4, TimeSpan.FromSeconds(1));
            var opacity = new System.Windows.Media.Animation.DoubleAnimation(1, 0, TimeSpan.FromSeconds(1));

            System.Windows.Media.Animation.Storyboard.SetTarget(scaleX, PulseRing);
            System.Windows.Media.Animation.Storyboard.SetTargetProperty(scaleX, new PropertyPath("(UIElement.RenderTransform).(ScaleTransform.ScaleX)"));

            System.Windows.Media.Animation.Storyboard.SetTarget(scaleY, PulseRing);
            System.Windows.Media.Animation.Storyboard.SetTargetProperty(scaleY, new PropertyPath("(UIElement.RenderTransform).(ScaleTransform.ScaleY)"));

            System.Windows.Media.Animation.Storyboard.SetTarget(opacity, PulseRing);
            System.Windows.Media.Animation.Storyboard.SetTargetProperty(opacity, new PropertyPath("Opacity"));

            _pulseStoryboard.Children.Add(scaleX);
            _pulseStoryboard.Children.Add(scaleY);
            _pulseStoryboard.Children.Add(opacity);

            PulseRing.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);
            PulseRing.RenderTransform = new System.Windows.Media.ScaleTransform(1, 1);
        }

        private async void ExecuteScanInternal(Func<IEnumerable<ScanResult>> scanAction)
        {
            TxtStatus.Text = "Scanning... Gravity Wave Active.";
            _results.Clear();

            if (_pulseStoryboard != null)
            {
                PulseRing.Visibility = Visibility.Visible;
                _pulseStoryboard.Begin();
            }

            var scanResults = await Task.Run(scanAction);
            foreach (var r in scanResults)
            {
                Dispatcher.Invoke(() => _results.Add(r));
            }

            if (_pulseStoryboard != null)
            {
                _pulseStoryboard.Stop();
                PulseRing.Visibility = Visibility.Hidden;
            }

            int threats = _results.Count(x => x.IsMalicious);
            TxtStatus.Text = $"Scan complete. Found {threats} threats out of {_results.Count} files.";
            
            if (threats > 0)
            {
                var btn = (System.Windows.Controls.Button)this.FindName("BtnFixThreats");
                if (btn != null) btn.Visibility = Visibility.Visible;
            }
            else
            {
                var btn = (System.Windows.Controls.Button)this.FindName("BtnFixThreats");
                if (btn != null) btn.Visibility = Visibility.Collapsed;
            }

            _log.Info(TxtStatus.Text);
        }

        private void BtnScanFolder_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new System.Windows.Forms.FolderBrowserDialog();
            var result = dlg.ShowDialog();
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                _settings.Current.LastScanFolder = dlg.SelectedPath;
                _settings.Save();

                TxtStatus.Text = $"Scanning {dlg.SelectedPath}...";
                ExecuteScanInternal(() => _scanner.ScanFolder(dlg.SelectedPath));
            }
        }

        private void BtnChooseFolder_Click(object sender, RoutedEventArgs e)
        {
            BtnScanFolder_Click(sender, e);
        }

        private void BtnShieldScan_Click(object sender, RoutedEventArgs e)
        {
            ExecuteScanInternal(() => _presetScan.RunShieldScan());
        }

        private void BtnScanStartup_Click(object sender, RoutedEventArgs e)
        {
            ExecuteScanInternal(() => _startupScanner.ScanStartupLocations());
        }

        private void BtnFixThreats_Click(object sender, RoutedEventArgs e)
        {
            var maliciousItems = _results.Where(r => r.IsMalicious).ToList();
            int successCount = 0;

            foreach (var item in maliciousItems)
            {
                try
                {
                    _quarantineManager.QuarantineFile(item.FilePath, item.DetectionReason);
                    _results.Remove(item);
                    successCount++;
                }
                catch (Exception ex)
                {
                    _log.Error($"Failed to quarantine {item.FilePath}: {ex.Message}");
                }
            }

            var btn = (System.Windows.Controls.Button)this.FindName("BtnFixThreats");
            if (btn != null) btn.Visibility = Visibility.Collapsed;
            
            TxtStatus.Text = $"Quarantined {successCount} threats.";
            System.Windows.MessageBox.Show($"Successfully isolated {successCount} threats to Quarantine.", "Threats Fixed", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
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
                var newScanner = new FileScanner(signatureEngine, heuristicEngine, _settings);
                
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

                // Swap the reference in the Active Monitor
                var monitorField = this.GetType().GetField("_activeMonitor", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                if (monitorField != null)
                {
                    var oldMonitor = (ActiveMonitorService?)monitorField.GetValue(this);
                    oldMonitor?.StopMonitoring();
                    oldMonitor?.Dispose();

                    var newMonitor = new ActiveMonitorService(newScanner, _log);
                    newMonitor.OnThreatIntercepted += ActiveMonitor_OnThreatIntercepted;
                    if (_settings.Current.EnableActiveProtection)
                    {
                        newMonitor.StartMonitoring();
                    }
                    monitorField.SetValue(this, newMonitor);
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

        private void ActiveMonitor_OnThreatIntercepted(object? sender, string message)
        {
            Dispatcher.Invoke(() =>
            {
                System.Windows.MessageBox.Show(message, "Real-Time Intercept", MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }

        private void ChkActiveProtection_CheckedChanged(object sender, RoutedEventArgs e)
        {
            if (ChkActiveProtection.IsChecked == true)
            {
                _settings.Current.EnableActiveProtection = true;
                _activeMonitor.StartMonitoring();
                TxtStatus.Text = "Active Protection Enabled.";
            }
            else
            {
                _settings.Current.EnableActiveProtection = false;
                _activeMonitor.StopMonitoring();
                TxtStatus.Text = "Active Protection Disabled.";
            }
            _settings.Save();
        }
    }
}