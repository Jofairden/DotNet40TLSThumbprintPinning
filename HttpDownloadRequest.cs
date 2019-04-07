using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32;

namespace DotNet40TLSThumbprintPinning
{
	/// <summary>
	/// Defines a file download request that will use an underlying HttpWebRequest
	/// </summary>
	internal sealed class HttpDownloadRequest : DownloadRequest
	{
		// The function should return the underlying HttpWebRequest to use
		// It will use correct registry values and ServicePoint settings
		// By being lazily evaluated
		private readonly Func<HttpWebRequest> _requestCallback;

		// The underlying request
		public HttpWebRequest Request { get; private set; }

		// Various settings
		public const SecurityProtocolType Tls12 = (SecurityProtocolType) 3072;
		public SecurityProtocolType SecurityProtocol = Tls12;
		public Version ProtocolVersion = HttpVersion.Version11;

		public HttpDownloadRequest(string filename, Func<HttpWebRequest> requestCallback, Action callback)
			: base(filename, callback)
		{
			_requestCallback = requestCallback;
		}

		public override bool SetupRequest()
		{
			if (!EnsureTlsSupport())
			{
				Console.WriteLine("Could not ensure Tls support, aborting request.");
				return false;
			}

			ServicePointManager.SecurityProtocol = SecurityProtocol;
			// You can choose to support other protocols too, e.g: 
			// SecurityProtocol |= SecurityProtocolType.Ssl3

			ServicePointManager.ServerCertificateValidationCallback = ServerCertificateValidation;

			Request = _requestCallback();
			Request.ProtocolVersion = ProtocolVersion;
			Request.UserAgent = "DotNet40TLSThumbprintPinning/1.0 (Windows; Win32)";

			// We may not want to set TCP here, there is no long polling and server /should/ respond
			// We could set a timeout instead
			// Request.ServicePoint.SetTcpKeepAlive(true, 1500, 1500);
			return true;
		}

		// To verify the server certificate there is many things we could do
		// Recommended is any form of certificate pinning
		// You could perform certificate pinning, public key pinning or thumbprint pinning, each with their own
		// advantages and disadvantages.
		// The pinning goes past checking the trust store and Root CA
		// See also: https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning
		//           https://tools.ietf.org/html/rfc7469
		//           https://morgansimonsen.com/2013/04/16/understanding-x-509-digital-certificate-thumbprints/
		//           https://www.symantec.com/content/dam/symantec/docs/white-papers/certificate-pinning-en.pdf
		// Note, HPKP is mostly being dropped, see: https://www.theregister.co.uk/2017/10/30/google_hpkp/
		// However, HPKP is still pretty versatile and improves security (safeguards against MITM attacks)
		// The successor of the HPKP header is the Expect-CT header,
		// Read more about it here: https://tools.ietf.org/html/draft-ietf-httpbis-expect-ct-02
		// And here: https://httpwg.org/http-extensions/expect-ct.html
		// In our case, using Tls is enough to connect to Github,
		// We can perform our own level of pinning to ensure we are receiving a legitimate certificate
		// See below for sample implementations
		private bool ServerCertificateValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
		{
			if (errors != SslPolicyErrors.None
			    || certificate == null
			    || chain == null)
				return false;

			return ThumbprintPin(certificate);
		}

		// A very easy way that requires to third party tools is SHA-1 Thumbprint pinning,
		// which only requires four (4) SHA-1 hashes, two for each subject (Github & AmazonAWS)
		// and both having a primary and secondary (backup) pin
		// The con of this method is that you have to update the known thumbprint
		// when the server rotates its certificates, as the SHA-1 hash is derived from the entire
		// contents of the certificate. The pro is that it is most easy to setup
		private readonly string[] _knownThumbprints =
		{
			"CA06F56B258B7A0D4F2B05470939478651151984", // Primary   // SHA-256: 3111500C4A66012CDAE333EC3FCA1C9DDE45C954440E7EE413716BFF3663C074 (Github)    https://crt.sh/?id=455589305
			"BC68654504238483E464AE83A989A8E466257671", // Secondary // SHA-256: D2C4AF4907236A9B8614DF1DE04D522928B71B0126A83AD9857B9967FE6BAD4C (Github)    https://crt.sh/?id=449619899
			"17E0A93E58AF0A068D6C2DB6C180B3E7E352D48E", // Primary   // SHA-256: B23E9F6A3D8E36AE8EDA01D6EA76E743DCEC15922BD8EF5F90A6E0E7D223E020 (AmazonAWS) https://crt.sh/?id=949340748
			"3070C15E74246B57D2ABB2A8435528322F5DCF74", // Secondary // SHA-256: D40CC4EC370D107D80D1512D488C7B335D5F6FD52969A97A87221E04E8A7A94A (AmazonAWS) https://crt.sh/?id=927633594
		};
		private bool ThumbprintPin(X509Certificate certificate)
		{
			string thumbPrint = ((X509Certificate2) certificate).Thumbprint;
			if (Request.RequestUri.GetLeftPart(UriPartial.Authority).StartsWith("https://github"))
			{
				return thumbPrint != null && _knownThumbprints.Contains(thumbPrint);
			}

			return false;
		}

		// Another method is actual public key pinning
		// This is trickier, as you need third party tools to get the actual public keys or find them online.
		// You can calculate the public key with the modulus and calculus of the certificate.
		// OpenSSL Download: https://slproweb.com/products/Win32OpenSSL.html
		// Possibly the best method is full certificate pinning
		// Essentially, you compare the sent certificate against your local (trusted one)

		// Enforce that .NET 4.0 will use strong cryptography
		// and allows setting Tls versions other than OS default
		// This requires a registry edit and will prompt UAC
		// See: https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#for-net-framework-35---452-and-not-wcf
		private bool EnsureTlsSupport()
		{
			const string netVersion = "v4.0.30319"; // .NET 4.0
			string registryPath = $"SOFTWARE\\Microsoft\\.NETFramework\\{netVersion}";

			// For the 64 path:
			// string registryPathX64 = $"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\{netVersion}";

			try
			{
				// The registry values we need to write
				const string schUseStrongCryptoStr = "SchUseStrongCrypto";
				const string systemDefaultTlsVersionsStr = "SystemDefaultTlsVersions";

				var identity = WindowsIdentity.GetCurrent();
				var principal = new WindowsPrincipal(identity);
				var regKey = Registry.LocalMachine.OpenSubKey(registryPath, writable: false);

				Console.WriteLine($"Checking {schUseStrongCryptoStr} and {systemDefaultTlsVersionsStr} registry values");

				bool updateSchUseStrongCrypto = !regKey?.GetValue(schUseStrongCryptoStr)?.ToString().Equals("1") ?? true;
				bool updateSystemDefaultTlsVersions = !regKey?.GetValue(systemDefaultTlsVersionsStr)?.ToString().Equals("1") ?? true;

				if (!updateSchUseStrongCrypto && !updateSystemDefaultTlsVersions)
				{
					Console.WriteLine("Registry values to support TLS are correct.");
					return true;
				}

				// If we have privileges, we can modify registry directly.
				if (principal.IsInRole(WindowsBuiltInRole.Administrator))
				{
					regKey = Registry.LocalMachine.OpenSubKey(registryPath, writable: true);
					Console.WriteLine("User is administrator privileged, proceeding to adjust SchUseStrongCrypto and SystemDefaultTlsVersions registry values");

					if (regKey == null)
						return false;

					// NET 4.6 and up defaults SchUseStrongCrypto to 1
					// NET 4.7 and up defaults SystemDefaultTlsVersions to 1

					// This key should only have a value of 0 if we need to connect to legacy services that don't support strong cryptography and can't be upgraded.
					// But we don't, we should enforce TLS with strong crypto, especially from github as it supports it and enforces TLS
					regKey.SetValue(schUseStrongCryptoStr, 1, RegistryValueKind.DWord);
					regKey.SetValue(systemDefaultTlsVersionsStr, 1, RegistryValueKind.DWord);
					regKey.Close();
					regKey.Dispose();
				}
				else
				{
					// We do not have privileges, but we can prompt UAC by starting a new process
					Console.WriteLine("User is NOT administrator privileged, proceeding prompt UAC and run registry edit");
					var process = new Process
					{
						EnableRaisingEvents = true,
						StartInfo = new ProcessStartInfo
						{
							WindowStyle = ProcessWindowStyle.Normal,
							// REQUIRED true, cannot prompt  UAC if false
							// BUT also cannot redirect if true (downside)
							UseShellExecute = true,
							FileName = "regedit.exe",
							Arguments = $"\"{Environment.CurrentDirectory}\\EnsureTlsSupportWIN.REG\"",
							Verb = "runas",
							CreateNoWindow = false
						}
					};
					process.Start();
					process.WaitForExit();
				}

				return true;
			}
			catch (Exception e)
			{
				Console.WriteLine(e.ToString());
				return false;
			}
		}
	}
}
