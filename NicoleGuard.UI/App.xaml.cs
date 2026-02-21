using System.Windows;

namespace NicoleGuard.UI
{
    public partial class App : System.Windows.Application
    {
        public void ApplyTheme(string themeName)
        {
            Resources.MergedDictionaries.Clear();
            Resources.MergedDictionaries.Add(
                new System.Windows.ResourceDictionary { Source = new System.Uri($"Themes/{themeName}.xaml", System.UriKind.Relative) }
            );
        }
    }
}
