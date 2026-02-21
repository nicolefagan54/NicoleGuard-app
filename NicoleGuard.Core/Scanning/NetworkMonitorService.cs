using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Scanning
{
    public class NetworkMonitorService
    {
        private readonly Services.LogService _log;

        public NetworkMonitorService(Services.LogService log)
        {
            _log = log;
        }

        public IEnumerable<NetworkConnectionInfo> GetActiveConnections()
        {
            var connections = new List<NetworkConnectionInfo>();
            try
            {
                var psi = new ProcessStartInfo("netstat", "-ano")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process == null) return connections;

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                
                // netstat -ano output format:
                // Proto  Local Address          Foreign Address        State           PID
                // TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1200
                // UDP    0.0.0.0:5050           *:*                                    2044

                foreach (var line in lines)
                {
                    var parts = Regex.Split(line.Trim(), @"\s+");
                    if (parts.Length < 4) continue;

                    string proto = parts[0];
                    if (proto != "TCP" && proto != "UDP") continue;

                    string local = parts[1];
                    string remote = parts[2];
                    string state = proto == "TCP" ? parts[3] : "";
                    string pidStr = proto == "TCP" ? parts[4] : parts[3];

                    if (int.TryParse(pidStr, out int pid))
                    {
                        string pName = "Unknown";
                        try
                        {
                            var proc = Process.GetProcessById(pid);
                            pName = proc.ProcessName;
                        }
                        catch
                        {
                            // Process might have exited or Access Denied
                        }

                        connections.Add(new NetworkConnectionInfo
                        {
                            Protocol = proto,
                            LocalAddress = local,
                            RemoteAddress = remote,
                            State = state,
                            ProcessId = pid,
                            ProcessName = pName
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Error($"Failed to get network connections: {ex.Message}");
            }

            return connections;
        }
    }
}
