using System;
using System.Drawing;
using System.Windows.Forms;

namespace NicoleGuard.UI.Services
{
    public class NotificationService : IDisposable
    {
        private readonly NotifyIcon _notifyIcon;

        public NotificationService()
        {
            _notifyIcon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Visible = true,
                Text = "NicoleGuard Antivirus"
            };
        }

        public void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
        {
            _notifyIcon.ShowBalloonTip(3000, title, message, icon);
        }

        public void Dispose()
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
        }
    }
}
