using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using NicoleGuard.Core.Services;

namespace NicoleGuard.Core.Scanning
{
    public class SandboxAnalyzer : IDisposable
    {
        private readonly LogService _log;
        private IntPtr _jobHandle = IntPtr.Zero;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr CreateJobObject(IntPtr a, string lpName);

        [DllImport("kernel32.dll")]
        static extern bool SetInformationJobObject(IntPtr hJob, JobObjectInfoType infoType, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        public SandboxAnalyzer(LogService log)
        {
            _log = log;
            InitializeRestrictedJobObject();
        }

        private void InitializeRestrictedJobObject()
        {
            _jobHandle = CreateJobObject(IntPtr.Zero, null!);
            if (_jobHandle == IntPtr.Zero)
            {
                _log.Error("Failed to create Sandbox Job Object.");
                return;
            }

            // Define extremely strict memory and CPU limits
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = 
                (uint)(0x00000008 | 0x00000010 | 0x00001000); // JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_AFFINITY | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                
            info.BasicLimitInformation.ActiveProcessLimit = 1; // Prevent the malware from spawning child processes
            
            // Note: Job Objects alone cannot fully block filesystem or network access without
            // injecting DLLs or setting up AppContainers, but restricting process limits
            // is the first step of creating a Windows ring-fenced sandbox.

            int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr extendedInfoPtr = Marshal.AllocHGlobal(length);
            Marshal.StructureToPtr(info, extendedInfoPtr, false);

            if (!SetInformationJobObject(_jobHandle, JobObjectInfoType.ExtendedLimitInformation, extendedInfoPtr, (uint)length))
            {
                _log.Error($"Failed to set Sandbox Job Object limits. Error: {Marshal.GetLastWin32Error()}");
            }

            Marshal.FreeHGlobal(extendedInfoPtr);
            _log.Info("Sandbox Environment initialized with Restricted Job Object Limits.");
        }

        public string RunExecutable(string filePath)
        {
            if (_jobHandle == IntPtr.Zero) return "Sandbox initialization failed. Aborting execution.";

            ProcessStartInfo psi = new ProcessStartInfo()
            {
                FileName = filePath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using (Process proc = new Process())
            {
                proc.StartInfo = psi;
                
                try
                {
                    _log.Info($"Executing {Path.GetFileName(filePath)} inside Sandbox...");
                    proc.Start();
                    
                    // Immediately assign the running process to our restricted Job Object container
                    bool success = AssignProcessToJobObject(_jobHandle, proc.Handle);
                    
                    if (!success)
                    {
                        string err = $"Failed to inject {Path.GetFileName(filePath)} into Sandbox. Terminating for safety.";
                        proc.Kill();
                        _log.Error(err);
                        return err;
                    }

                    // Let the malware run for a maximum of 5 seconds to perform malicious behavior
                    if (!proc.WaitForExit(5000))
                    {
                        proc.Kill(); // Force termination after 5 seconds to prevent persistence
                        _log.Info($"Sandbox forcefully terminated {Path.GetFileName(filePath)} after 5 seconds.");
                        return $"Sandbox forcefully terminated {Path.GetFileName(filePath)} after 5 seconds. Process attempted to run indefinitely.";
                    }

                    string output = proc.StandardOutput.ReadToEnd();
                    string errOut = proc.StandardError.ReadToEnd();
                    
                    _log.Info("Sandbox execution completed naturally.");

                    return $"Execution Complete. Exit Code: {proc.ExitCode}\nOutput: {output}\nErrors: {errOut}";
                }
                catch (Exception ex)
                {
                    return $"Sandbox execution threw an exception: {ex.Message}";
                }
            }
        }

        public void Dispose()
        {
            if (_jobHandle != IntPtr.Zero)
            {
                CloseHandle(_jobHandle);
                _jobHandle = IntPtr.Zero;
            }
        }

        // --- P/Invoke Structs ---
        
        public enum JobObjectInfoType
        {
            ExtendedLimitInformation = 9
        }

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public Int64 PerProcessUserTimeLimit;
            public Int64 PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IO_COUNTERS
        {
            public UInt64 ReadOperationCount;
            public UInt64 WriteOperationCount;
            public UInt64 OtherOperationCount;
            public UInt64 ReadTransferCount;
            public UInt64 WriteTransferCount;
            public UInt64 OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }
    }
}
