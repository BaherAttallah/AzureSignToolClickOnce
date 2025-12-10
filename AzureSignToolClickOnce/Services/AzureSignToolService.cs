using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using AzureSign.Core;
using AzureSignToolClickOnce.Utils;
using RSAKeyVaultProvider;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AzureSignToolClickOnce.Services
{
    public class AzureSignToolService
    {
        private const string DotnetMageVersion = "9.0.0";
        
        public void Start(string description, string path, string timeStampUrl, string timeStampUrlRfc3161, string keyVaultUrl, string tenantId, string clientId, string clientSecret, string certName)
        {
            // Ensure dotnet-mage is installed before proceeding
            EnsureDotnetMageInstalled();

            var tokenCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            var client = new CertificateClient(vaultUri: new Uri(keyVaultUrl), credential: tokenCredential);
            var cert = client.GetCertificate(certName).Value;
            var certificate = new X509Certificate2(cert.Cer);
            var keyIdentifier = cert.KeyId;
            var rsa = RSAFactory.Create(tokenCredential, keyIdentifier, certificate);

            // We need to be explicit about the order these files are signed in. The data files must be signed first
            // Then the .manifest file
            // Then the nested clickonce/vsto file
            // finally the top-level clickonce/vsto file

            // MAM: Handle Deploy files. Get Rawfiles first.
            var rawfiles = Directory.GetFiles(path, "*.*").ToList();
            if (Directory.Exists(path + @"\Application Files"))
            {
                rawfiles.AddRange(Directory.GetFiles(path + @"\Application Files", "*.*", SearchOption.AllDirectories));
            }
            for (int i = 0; i < rawfiles.Count; i++)
            {
                string file = rawfiles[i];
                rawfiles[i] = file.Replace(@"\\", @"\");
            }

            List<string> files = new List<string>();

            // Rename deploy files if needed and track renames
            List<string> deployFiles = new List<string>();
            foreach (string filename in rawfiles)
            {
                if (filename.EndsWith(".deploy", StringComparison.OrdinalIgnoreCase))
                {
                    FileInfo info = new FileInfo(filename);
                    string newName = filename.Substring(0, filename.Length - 7);
                    
                    // If target file already exists, delete it first
                    if (File.Exists(newName))
                    {
                        Console.WriteLine($"Target file already exists, deleting: {newName}");
                        File.Delete(newName);
                    }
                    
                    info.MoveTo(newName);
                    deployFiles.Add(newName);
                    files.Add(newName);
                }
                else
                {
                    files.Add(filename);
                }
            }

            var filesToSign = new List<string>();
            var setupExe = files.Where(f => ".exe".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase));
            filesToSign.AddRange(setupExe);

            // Find manifest files - there might be multiple in different version folders
            var manifestFiles = files.Where(f => ".manifest".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase)).ToList();
            
            if (manifestFiles.Count == 0)
            {
                Console.WriteLine("No manifest file found");
                return;
            }
            
            if (manifestFiles.Count > 1)
            {
                Console.WriteLine($"Warning: Found {manifestFiles.Count} manifest files:");
                foreach (var mf in manifestFiles)
                {
                    Console.WriteLine($"  - {mf}");
                }
            }
            
            // Select the appropriate manifest file:
            // 1. Prefer manifest files in the root publish directory (not in Application Files subdirectory)
            // 2. If multiple manifests in Application Files, select from the most recent version folder
            var rootManifests = manifestFiles.Where(f => !f.Contains(@"\Application Files\")).ToList();
            
            string manifestFile;
            if (rootManifests.Any())
            {
                // Use the root manifest if available
                manifestFile = rootManifests.First();
                Console.WriteLine($"Using root manifest file: {manifestFile}");
            }
            else
            {
                // No root manifest, so select from Application Files
                // Sort by path descending to get the latest version (assuming version folders sort alphabetically)
                manifestFile = manifestFiles.OrderByDescending(f => f).First();
                Console.WriteLine($"Using manifest from Application Files (latest version): {manifestFile}");
            }

            // sign the exe files
            SignInAzureVault(description, "", timeStampUrlRfc3161, certificate, rsa, filesToSign);

            // look for the manifest file and sign that
            var args = "-a sha256RSA";
            var fileArgs = $@"-update ""{manifestFile}"" {args}";
            if (!RunDotnetMageTool(fileArgs, manifestFile, rsa, certificate, timeStampUrl))
                return;

            // Now sign the inner vsto/clickonce file
            // Order by desending length to put the inner one first
            var clickOnceFilesToSign = files
                                            .Where(f => ".vsto".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase) ||
                                                        ".application".Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase))
                                            .Select(f => new { file = f, f.Length })
                                            .OrderByDescending(f => f.Length)
                                            .Select(f => f.file)
                                            .ToList();

            // Get relative path to the manifest file
            var manifestRelativePath = GetRelativeFilePath(manifestFile, path);

            foreach (var f in clickOnceFilesToSign)
            {
                fileArgs = $@"-update ""{f}"" {args} -appm ""{manifestFile}"" -appc ""{manifestRelativePath}""";
                if (!RunDotnetMageTool(fileArgs, f, rsa, certificate, timeStampUrl))
                {
                    throw new Exception($"Could not sign {f}");
                }
            }

            // rename deploy files back to original
            foreach (string filename in deployFiles)
            {
                string deployFileName = filename.Trim() + ".deploy";
                
                // If the .deploy file already exists, delete it first
                if (File.Exists(deployFileName))
                {
                    Console.WriteLine($"Deploy file already exists, deleting: {deployFileName}");
                    File.Delete(deployFileName);
                }
                
                File.Move(filename, deployFileName);
            }
        }

        private string GetRelativeFilePath(string filePath, string basePath)
        {
            if (filePath.Contains(basePath))
            {
                return filePath.Substring(basePath.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            return filePath;
        }

        private void SignInAzureVault(string description, string supportUrl, string timeStampUrlRfc3161, X509Certificate2 certificate, RSA rsaPrivateKey, List<string> filesToSign)
        {
            var authenticodeKeyVaultSigner = new AuthenticodeKeyVaultSigner(rsaPrivateKey, certificate, HashAlgorithmName.SHA256,
                new TimeStampConfiguration(timeStampUrlRfc3161, HashAlgorithmName.SHA256, TimeStampType.RFC3161));
            foreach (var f in filesToSign)
            {
                Console.WriteLine($"SignInAzureVault: {f}");
                authenticodeKeyVaultSigner.SignFile(f.AsSpan(), description.AsSpan(), supportUrl.AsSpan(), null);
            }
        }

        private void EnsureDotnetMageInstalled()
        {
            Console.WriteLine("Checking if dotnet-mage is installed...");
            
            // Check if dotnet-mage is installed
            var checkProcess = new Process
            {
                StartInfo =
                {
                    FileName = "dotnet",
                    Arguments = "tool list --global",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            checkProcess.Start();
            string output = checkProcess.StandardOutput.ReadToEnd();
            checkProcess.WaitForExit();

            if (!output.Contains("microsoft.dotnet.mage"))
            {
                Console.WriteLine($"dotnet-mage not found. Installing version {DotnetMageVersion}...");
                InstallDotnetMage();
            }
            else
            {
                Console.WriteLine("dotnet-mage is already installed.");
            }
        }

        private void InstallDotnetMage()
        {
            var installProcess = new Process
            {
                StartInfo =
                {
                    FileName = "dotnet",
                    Arguments = $"tool install --global Microsoft.DotNet.Mage --version {DotnetMageVersion}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            Console.WriteLine($"Running: dotnet tool install --global Microsoft.DotNet.Mage --version {DotnetMageVersion}");
            
            installProcess.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    Console.WriteLine($"Install Output: {e.Data}");
            };
            
            installProcess.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    Console.WriteLine($"Install Error: {e.Data}");
            };

            installProcess.Start();
            installProcess.BeginOutputReadLine();
            installProcess.BeginErrorReadLine();
            installProcess.WaitForExit();

            if (installProcess.ExitCode == 0)
            {
                Console.WriteLine("dotnet-mage installed successfully.");
            }
            else
            {
                throw new Exception($"Failed to install dotnet-mage. Exit code: {installProcess.ExitCode}");
            }
        }

        private bool RunDotnetMageTool(string args, string inputFile, RSA rsa, X509Certificate2 publicCertificate, string timestampUrl)
        {
            var mageProcess = new Process
            {
                StartInfo =
                {
                    FileName = "dotnet",
                    Arguments = $"mage {args}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true
                }
            };
            
            Console.WriteLine($"Signing with dotnet-mage: {mageProcess.StartInfo.FileName} {mageProcess.StartInfo.Arguments}");
            
            mageProcess.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    Console.WriteLine($"Mage Out: {e.Data}");
            };
            
            mageProcess.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    Console.WriteLine($"Mage Err: {e.Data}");
            };

            mageProcess.Start();
            mageProcess.BeginOutputReadLine();
            mageProcess.BeginErrorReadLine();
            mageProcess.WaitForExit();

            if (mageProcess.ExitCode == 0)
            {
                Console.WriteLine($"Manifest signing {inputFile}");
                ManifestSigner.SignFile(inputFile, rsa, publicCertificate, timestampUrl);
                return true;
            }

            Console.WriteLine($"Error: dotnet-mage returned {mageProcess.ExitCode}");
            return false;
        }
    }
}
