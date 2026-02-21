using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using NicoleGuard.Core.Scanning;
using NicoleGuard.Core.Services;

namespace NicoleGuard.UI.Views
{
    public partial class SandboxWindow : Window
    {
        private readonly SandboxAnalyzer _sandbox;
        private readonly string _targetExePath;

        public SandboxWindow(string exePath, LogService log)
        {
            InitializeComponent();
            _targetExePath = exePath;
            
            // Generate the restricted Job Object Sandbox
            _sandbox = new SandboxAnalyzer(log);

            TxtStatus.Text = $"Target loaded: {Path.GetFileName(_targetExePath)}\nStatus: Isolated in Job Object container. Ready for safe execution.";
        }

        private async void BtnRun_Click(object sender, RoutedEventArgs e)
        {
            BtnRun.IsEnabled = false;
            TxtStatus.Text = "Status: Executing payload inside Sandbox ring...";
            TxtOutput.Text = $"[System] Injecting {Path.GetFileName(_targetExePath)} into Restricted Job Object...\n";

            try
            {
                // Run the sandbox simulation on a background thread so we don't freeze the WPF UI
                string result = await Task.Run(() => _sandbox.RunExecutable(_targetExePath));

                TxtOutput.Text += "\n--- EXECUTION REPORT ---\n";
                TxtOutput.Text += result;
                
                TxtStatus.Text = "Status: Execution completed. Review telemetry log below.";
            }
            catch (Exception ex)
            {
                TxtOutput.Text += $"\n[CRITICAL ERROR] Sandbox container breached or crashed: {ex.Message}";
                TxtStatus.Text = "Status: Execution Failed.";
            }
            finally
            {
                BtnRun.IsEnabled = true;
            }
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            _sandbox.Dispose(); // Clean up Kernel handles
            this.Close();
        }

        protected override void OnClosed(EventArgs e)
        {
            _sandbox.Dispose();
            base.OnClosed(e);
        }
    }
}
