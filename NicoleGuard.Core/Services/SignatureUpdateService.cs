using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace NicoleGuard.Core.Services
{
    public class SignatureUpdateService
    {
        private readonly string _badHashesPath;
        private readonly LogService _log;
        private static readonly HttpClient _httpClient = new HttpClient();

        // The raw URL to the latest signatures hosted on your GitHub
        private const string SignatureUrl = "https://raw.githubusercontent.com/nicolefagan54/NicoleGuard-app/main/NicoleGuard.Data/bad_hashes.json";

        public SignatureUpdateService(string dataFolder, LogService log)
        {
            _badHashesPath = Path.Combine(dataFolder, "bad_hashes.json");
            _log = log;
        }

        public async Task<bool> UpdateSignaturesAsync()
        {
            try
            {
                _log.Info("Attempting to fetch latest signatures from GitHub...");
                
                var response = await _httpClient.GetAsync(SignatureUrl);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();

                // Validate it's actual JSON (basic check) before overwriting
                if (json.Contains("\"bad_hashes\""))
                {
                    File.WriteAllText(_badHashesPath, json);
                    _log.Info("Signatures updated successfully.");
                    return true;
                }
                else
                {
                    _log.Error("Signature update aborted: Invalid JSON format received.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _log.Error($"Failed to update signatures: {ex.Message}");
                return false;
            }
        }
    }
}
