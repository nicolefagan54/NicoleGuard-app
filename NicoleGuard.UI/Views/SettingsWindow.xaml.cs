using System.Windows;
using System.Windows.Controls;
using NicoleGuard.Core.Services;
using System.Linq;

namespace NicoleGuard.UI.Views
{
    public partial class SettingsWindow : Window
    {
        private readonly SettingsService _settingsService;

        public SettingsWindow(SettingsService settingsService)
        {
            InitializeComponent();
            _settingsService = settingsService;
            LoadSettings();
        }

        private void LoadSettings()
        {
            CboTheme.SelectedIndex = _settingsService.Current.ThemeMode == "Light" ? 1 : 0;
            ListExclusions.ItemsSource = _settingsService.Current.ExcludedExtensions.ToList();
        }

        private void CboTheme_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CboTheme.SelectedItem is ComboBoxItem item)
            {
                var theme = item.Content?.ToString();
                if (theme != null) ((App)System.Windows.Application.Current).ApplyTheme(theme);
            }
        }

        private void BtnAddExt_Click(object sender, RoutedEventArgs e)
        {
            string ext = TxtExt.Text.Trim();
            if (!string.IsNullOrEmpty(ext))
            {
                if (!ext.StartsWith(".")) ext = "." + ext;
                
                var list = _settingsService.Current.ExcludedExtensions.ToList();
                if (!list.Contains(ext))
                {
                    list.Add(ext);
                    _settingsService.Current.ExcludedExtensions = list.ToArray();
                    ListExclusions.ItemsSource = list;
                }
                TxtExt.Text = "";
            }
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            if (CboTheme.SelectedItem is ComboBoxItem item)
            {
                _settingsService.Current.ThemeMode = item.Content?.ToString() ?? "Dark";
            }
            _settingsService.Save();
            System.Windows.MessageBox.Show("Settings Saved.", "Success", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            Close();
        }
    }
}
