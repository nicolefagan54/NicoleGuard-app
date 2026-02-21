using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using NicoleGuard.Core.Models;

namespace NicoleGuard.Core.Scanning
{
    public class ProcessMonitorService
    {
        private readonly Detection.SignatureVerificationService _sigVerifier;
        private readonly Services.LogService _log;

        public ProcessMonitorService(Detection.SignatureVerificationService sigVerifier, Services.LogService log)
        {
            _sigVerifier = sigVerifier;
            _log = log;
        }

        public IEnumerable<ProcessInfo> GetActiveProcesses()
        {
            var processes = Process.GetProcesses();
            var results = new List<ProcessInfo>();

            foreach (var p in processes)
            {
                try
                {
                    // Skip 'Idle' or 'System' which throw access denied usually
                    if (p.Id == 0 || p.Id == 4) continue;

                    string path = string.Empty;
                    try
                    {
                        path = p.MainModule?.FileName ?? string.Empty;
                    }
                    catch
                    {
                        // 32-bit vs 64-bit access issues or system processes
                        path = "Access Denied";
                    }

                    double memoryMb = p.WorkingSet64 / 1024.0 / 1024.0;
                    
                    string sigStatus = "Unknown";
                    string manufacturer = "Unknown";

                    // Only verify if we have a valid path
                    if (!string.IsNullOrEmpty(path) && path != "Access Denied" && System.IO.File.Exists(path))
                    {
                        sigStatus = _sigVerifier.VerifyFileSignature(path);
                        manufacturer = _sigVerifier.GetManufacturer(path);
                    }

                    results.Add(new ProcessInfo
                    {
                        ProcessId = p.Id,
                        ProcessName = p.ProcessName,
                        FilePath = path,
                        MemoryUsageMB = Math.Round(memoryMb, 2),
                        SignatureStatus = sigStatus,
                        Manufacturer = manufacturer
                    });
                }
                catch (Exception ex)
                {
                    _log.Error($"ProcessMonitor skipping PID {p.Id}: {ex.Message}");
                }
            }

            return results.OrderByDescending(x => x.MemoryUsageMB);
        }
    }
}
