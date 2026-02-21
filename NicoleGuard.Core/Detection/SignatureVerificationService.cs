using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace NicoleGuard.Core.Detection
{
    public class SignatureVerificationService
    {
        #region WinTrust P/Invoke
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const int WTD_UI_NONE = 2;
        private const int WTD_REVOKE_NONE = 0;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_STATEACTION_IGNORE = 0;
        private const int WTD_STATEACTION_VERIFY = 1;
        private const int WTD_STATEACTION_CLOSE = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WINTRUST_FILE_INFO : IDisposable
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            public IntPtr pcwszFilePath;
            public IntPtr hFile = IntPtr.Zero;
            public IntPtr pgKnownSubject = IntPtr.Zero;

            public WINTRUST_FILE_INFO(string _filePath)
            {
                pcwszFilePath = Marshal.StringToCoTaskMemAuto(_filePath);
            }
            public void Dispose()
            {
                if (pcwszFilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pcwszFilePath);
                    pcwszFilePath = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WINTRUST_DATA : IDisposable
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            public IntPtr pPolicyCallbackData = IntPtr.Zero;
            public IntPtr pSIPClientData = IntPtr.Zero;
            public uint dwUIChoice = WTD_UI_NONE;
            public uint fdwRevocationChecks = WTD_REVOKE_NONE;
            public uint dwUnionChoice = WTD_CHOICE_FILE;
            public IntPtr pFile;
            public uint dwStateAction = WTD_STATEACTION_IGNORE;
            public IntPtr hWVTStateData = IntPtr.Zero;
            public IntPtr pwszURLReference = IntPtr.Zero;
            public uint dwProvFlags = 0;
            public uint dwUIContext = 0;
            public IntPtr pSignatureSettings = IntPtr.Zero;

            public WINTRUST_DATA(WINTRUST_FILE_INFO _fileInfo)
            {
                pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(_fileInfo, pFile, false);
            }
            public void Dispose()
            {
                if (pFile != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                    Marshal.FreeCoTaskMem(pFile);
                    pFile = IntPtr.Zero;
                }
            }
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(
            [In] IntPtr hwnd,
            [In] [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            [In] WINTRUST_DATA pWVTData
        );
        #endregion

        // WINTRUST_ACTION_GENERIC_VERIFY_V2
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

        public string VerifyFileSignature(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !System.IO.File.Exists(filePath))
                return "File Not Found";

            // For efficiency, first try native .NET X509 checking
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(filePath);
                var cert2 = new X509Certificate2(cert);
                var isSigned = cert2.Verify();
                
                // If it's valid according to .NET, let's also pass it through WinVerifyTrust for confirmation
            }
            catch
            {
                // File probably doesn't have an embedded signature. 
                // WinVerifyTrust might still find a catalog signature.
            }

            int result = -1;
            using (var fileInfo = new WINTRUST_FILE_INFO(filePath))
            using (var data = new WINTRUST_DATA(fileInfo))
            {
                result = WinVerifyTrust(INVALID_HANDLE_VALUE, WINTRUST_ACTION_GENERIC_VERIFY_V2, data);
            }

            return result switch
            {
                0 => "Signed/Trusted", // TRUST_E_PROVIDER_UNKNOWN is usually 0x800B0001, 0 is ERROR_SUCCESS
                unchecked((int)0x800B0100) => "No Signature", // TRUST_E_NOSIGNATURE
                unchecked((int)0x800B0109) => "Untrusted Root", // CERT_E_UNTRUSTEDROOT
                unchecked((int)0x80096010) => "Invalid/Tampered", // TRUST_E_BAD_DIGEST
                _ => $"Unverified (0x{result:X})"
            };
        }
        
        public string GetManufacturer(string filePath)
        {
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(filePath);
                var cert2 = new X509Certificate2(cert);
                // Extract CN from Subject
                var subject = cert2.Subject;
                // Simple parse for CN=
                var parts = subject.Split(',');
                foreach (var part in parts)
                {
                    if (part.Trim().StartsWith("CN="))
                    {
                        return part.Trim().Substring(3);
                    }
                }
                return "Unknown Publisher";
            }
            catch
            {
                return "Unsigned/Unknown";
            }
        }
    }
}
