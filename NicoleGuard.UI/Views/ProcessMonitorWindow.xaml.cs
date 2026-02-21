using System.Windows;
using NicoleGuard.Core.Scanning;

namespace NicoleGuard.UI.Views
{
    public partial class ProcessMonitorWindow : Window
    {
        private readonly ProcessMonitorService _procService;
        private readonly NetworkMonitorService _netService;

        public ProcessMonitorWindow(ProcessMonitorService procService, NetworkMonitorService netService)
        {
            InitializeComponent();
            _procService = procService;
            _netService = netService;
            
            RefreshAll();
        }

        private void RefreshAll()
        {
            GridProcesses.ItemsSource = _procService.GetActiveProcesses();
            GridNetwork.ItemsSource = _netService.GetActiveConnections();
        }

        private void BtnRefreshOps_Click(object sender, RoutedEventArgs e)
        {
            GridProcesses.ItemsSource = _procService.GetActiveProcesses();
        }
        
        private void BtnRefreshNet_Click(object sender, RoutedEventArgs e)
        {
            GridNetwork.ItemsSource = _netService.GetActiveConnections();
        }
    }
}
