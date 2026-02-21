using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using NicoleGuard.Core.Models;
using NicoleGuard.Core.Quarantine;

namespace NicoleGuard.UI.Views
{
    public partial class QuarantineWindow : Window
    {
        private readonly QuarantineManager _manager;
        private readonly ObservableCollection<QuarantinedItem> _items = new();

        public QuarantineWindow(QuarantineManager manager)
        {
            InitializeComponent();
            _manager = manager;

            foreach (var item in _manager.Items)
                _items.Add(item);

            GridQuarantine.ItemsSource = _items;
        }

        private void Restore_Click(object sender, RoutedEventArgs e)
        {
            var selected = GridQuarantine.SelectedItem as QuarantinedItem;
            if (selected == null) return;

            if (_manager.Restore(selected.Id))
                _items.Remove(selected);
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            var selected = GridQuarantine.SelectedItem as QuarantinedItem;
            if (selected == null) return;

            if (_manager.Delete(selected.Id))
                _items.Remove(selected);
        }
    }
}
