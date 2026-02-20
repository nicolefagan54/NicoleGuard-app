using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using NicoleGuard.Core.Detection;
using NicoleGuard.Core.Quarantine;
using NicoleGuard.Core.Scanning;

namespace NicoleGuard.UI.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private readonly FileScanner _scanner;
        private readonly SignatureEngine _signatureEngine;
        private readonly HeuristicEngine _heuristicEngine;
        private readonly QuarantineManager _quarantineManager;
        
        private CancellationTokenSource? _cancellationTokenSource;

        public MainViewModel()
        {
            // Initialize Core components
            _scanner = new FileScanner();
            _scanner.ScanProgress += OnScanProgress;
            _scanner.FileScanned += OnFileScanned;

            // Use the application directory for data files
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string dataDir = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "NicoleGuard.Data"));
            
            _signatureEngine = new SignatureEngine(Path.Combine(dataDir, "bad_hashes.json"));
            _heuristicEngine = new HeuristicEngine();
            _quarantineManager = new QuarantineManager(dataDir);

            ScanResults = new ObservableCollection<ScanResult>();
            QuarantinedFiles = new ObservableCollection<QuarantinedFile>(_quarantineManager.GetQuarantinedFiles());

            StartScanCommand = new RelayCommand(ExecuteStartScan, CanExecuteStartScan);
            StopScanCommand = new RelayCommand(ExecuteStopScan, CanExecuteStopScan);
            QuarantineSelectedCommand = new RelayCommand(ExecuteQuarantineSelected, CanExecuteQuarantineSelected);
        }

        public ObservableCollection<ScanResult> ScanResults { get; }
        public ObservableCollection<QuarantinedFile> QuarantinedFiles { get; }

        private string _statusMessage = "Ready for scan. Select a folder to begin.";
        public string StatusMessage
        {
            get => _statusMessage;
            set => SetProperty(ref _statusMessage, value);
        }

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set
            {
                if (SetProperty(ref _isScanning, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private string _targetDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads";
        public string TargetDirectory
        {
            get => _targetDirectory;
            set => SetProperty(ref _targetDirectory, value);
        }

        private ScanResult? _selectedThreat;
        public ScanResult? SelectedThreat
        {
            get => _selectedThreat;
            set
            {
                if (SetProperty(ref _selectedThreat, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private int _totalFilesScanned;
        public int TotalFilesScanned
        {
            get => _totalFilesScanned;
            set => SetProperty(ref _totalFilesScanned, value);
        }

        private int _totalThreatsFound;
        public int TotalThreatsFound
        {
            get => _totalThreatsFound;
            set => SetProperty(ref _totalThreatsFound, value);
        }

        public ICommand StartScanCommand { get; }
        public ICommand StopScanCommand { get; }
        public ICommand QuarantineSelectedCommand { get; }

        private bool CanExecuteStartScan(object? parameter) => !IsScanning && Directory.Exists(TargetDirectory);

        private async void ExecuteStartScan(object? parameter)
        {
            IsScanning = true;
            ScanResults.Clear();
            TotalFilesScanned = 0;
            TotalThreatsFound = 0;
            StatusMessage = $"Starting scan of {TargetDirectory}...";

            _cancellationTokenSource = new CancellationTokenSource();

            try
            {
                await Task.Run(() => _scanner.ScanDirectory(TargetDirectory, _cancellationTokenSource.Token), _cancellationTokenSource.Token);
                StatusMessage = "Scan completed.";
            }
            catch (OperationCanceledException)
            {
                StatusMessage = "Scan cancelled.";
            }
            finally
            {
                IsScanning = false;
                _cancellationTokenSource.Dispose();
                _cancellationTokenSource = null;
            }
        }

        private bool CanExecuteStopScan(object? parameter) => IsScanning;

        private void ExecuteStopScan(object? parameter)
        {
            _cancellationTokenSource?.Cancel();
        }

        private bool CanExecuteQuarantineSelected(object? parameter) => SelectedThreat != null && !SelectedThreat.IsQuarantined;

        private void ExecuteQuarantineSelected(object? parameter)
        {
            if (SelectedThreat != null)
            {
                bool success = _quarantineManager.Quarantine(SelectedThreat.FilePath, SelectedThreat.ThreatName);
                if (success)
                {
                    SelectedThreat.IsQuarantined = true;
                    // Force UI update
                    var index = ScanResults.IndexOf(SelectedThreat);
                    ScanResults[index] = SelectedThreat;

                    // Update Quarantine list
                    QuarantinedFiles.Clear();
                    foreach (var file in _quarantineManager.GetQuarantinedFiles())
                    {
                        QuarantinedFiles.Add(file);
                    }
                    
                    MessageBox.Show($"Successfully quarantined: {SelectedThreat.FilePath}", "Quarantine Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show($"Failed to quarantine: {SelectedThreat.FilePath}", "Quarantine Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void OnScanProgress(object? sender, string message)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                StatusMessage = message;
            });
        }

        private void OnFileScanned(object? sender, ScanResult result)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                TotalFilesScanned++;

                // Analyze for threats
                bool isSignatureThreat = _signatureEngine.Analyze(result);
                bool isHeuristicThreat = false;
                
                if (!isSignatureThreat)
                {
                    isHeuristicThreat = _heuristicEngine.Analyze(result);
                }

                if (isSignatureThreat || isHeuristicThreat)
                {
                    TotalThreatsFound++;
                    ScanResults.Add(result);
                }
            });
        }
    }
}
