using System;
using System.Security.Cryptography.Asn1;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Toolchains.CoreRt;

namespace AsnBench
{
	class Program
	{
		static void Main(string[] args)
		{
			var config = DefaultConfig.Instance.With(Job.Default.With(Runtime.CoreRT));

			BenchmarkRunner.Run<X509Benchmark>(config);
			//BenchmarkRunner.Run<X509Benchmark>();
			//new X509Benchmark().Decode();
			//AsnSerializerGenerator.Deserialize<CertificateAsn>(X509Benchmark.certificateBytes, AsnEncodingRules.DER);
		}
	}

    [DisassemblyDiagnoser(printAsm: true, printSource: true)]
	public class X509Benchmark
	{
		internal static string MicrosoftDotComBase64 =
			@"
MIIFlDCCBHygAwIBAgIQPfcMXZkD+NiGi5uMzyDfaTANBgkqhkiG9w0BAQsFADB3
MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAd
BgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVj
IENsYXNzIDMgRVYgU1NMIENBIC0gRzMwHhcNMTQxMDE1MDAwMDAwWhcNMTYxMDE1
MjM1OTU5WjCCAQ8xEzARBgsrBgEEAYI3PAIBAxMCVVMxGzAZBgsrBgEEAYI3PAIB
AgwKV2FzaGluZ3RvbjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQ
BgNVBAUTCTYwMDQxMzQ4NTELMAkGA1UEBhMCVVMxDjAMBgNVBBEMBTk4MDUyMRMw
EQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdSZWRtb25kMRgwFgYDVQQJDA8x
IE1pY3Jvc29mdCBXYXkxHjAcBgNVBAoMFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEO
MAwGA1UECwwFTVNDT00xGjAYBgNVBAMMEXd3dy5taWNyb3NvZnQuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApGhh+p1dt2NjO/WmTvbnwsI2f0jS
1GZDoi38/Msk5YoU0PBr3JVkN/Kla6S+9wujYb8SlkoNZlr9hLD3SUyPpKvF/KLg
F8BheK7yza0bXxjpl6FLllwHTo9WSXBgcnawBYOTIkD+bi3QEwJvmuE9fJHMB8Th
6Oh3N9wG7ytXW4nWLv5GhZ+CVaEjaSpwbGgSLU2v4RyyBaez3gblU/e5X5eO+GAa
jfgZvzIEC9+SoN4N8mm0UUKC4XrGmTToRApIq50fXfiaUCzvbf2+eQBFvUXgyU5c
qK3XagE+nJeEQPyKniqaSUCyRggZw+MCqpyfNVrXVMhtPtd92qPaE4ELTQIDAQAB
o4IBgDCCAXwwMQYDVR0RBCowKIIRd3d3Lm1pY3Jvc29mdC5jb22CE3d3d3FhLm1p
Y3Jvc29mdC5jb20wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwYw
TDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUH
AgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEwHwYDVR0jBBgwFoAUAVmr5906
C1mmZGPWzyAHV9WR52owKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3NyLnN5bWNi
LmNvbS9zci5jcmwwVwYIKwYBBQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8v
c3Iuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpodHRwOi8vc3Iuc3ltY2IuY29tL3Ny
LmNydDANBgkqhkiG9w0BAQsFAAOCAQEAFfhQW2J+1/n5ZwcJfpOlHnp+BaPUIKXC
WOx6HP4YQ+wgrPcoqvp6GhvCIqfNv0r5CqJt7rOQnAs/tceAcNrj1kW/z4QKSj/d
mIx7Mwi/5Os/1mxFZB6WyjNS2+KutEiKZKnF+5aTK6cAWc6SvSeLQSmf0hNHG9gW
X5JCha4+zWZscDiF3KZdJNpm06+uOZaFIZlaTDmMffON+oKiA3LxPUpWrbIbWCJU
mRgBVke1+KwTHMXrJFNNFyvGAhioi2W89xx/OIzj4O9pe0IDcgSDu1eURVtZfYDU
jNOh1zy7xgnAWHZ9H/BgpgnX49QxcHmvDNCopJJRqxKRV/mJSgNkhw==
";

		internal static byte[] certificateBytes;
		//internal static AsnSerializer.Deserializer deserializer;

		static X509Benchmark()
		{
			certificateBytes = Convert.FromBase64String(MicrosoftDotComBase64);
			//deserializer = AsnSerializer.GetDeserializer(typeof(CertificateAsn), null);
			var certificate = new CertificateAsn
			{
				TbsCertificate = new TbsCertificateAsn
				{
					Validity = new ValidityAsn
					{
						NotAfter = new TimeAsn()
					},
					SignatureAlgorithm = new AlgorithmIdentifierAsn
					{
						Parameters = new ReadOnlyMemory<byte>(Array.Empty<byte>())
					},
					SubjectPublicKeyInfo = new SubjectPublicKeyInfoAsn
					{
					}
				}
			};
		}

		[Benchmark]
		public void Decode()
		{
			CertificateAsn.Decode(
				new AsnReader(certificateBytes, AsnEncodingRules.DER),
				out CertificateAsn certificate,
				out _);
			//AsnSerializer.Deserialize<CertificateAsn>(certificateBytes, AsnEncodingRules.DER);
			/*AsnReader reader = new AsnReader(certificateBytes, AsnEncodingRules.DER);

			CertificateAsn t = (CertificateAsn)deserializer(reader);

			reader.ThrowIfNotEmpty();
			//return t;*/
		}

		[Benchmark]
		public void DerSequenceReader()
		{
			new Internal.Cryptography.Pal.CertificateData(certificateBytes);
		}

		[Benchmark]
		public void AsnReader()
		{
			new Internal.Cryptography.Pal.CertificateDataAsn(certificateBytes);
		}
	}
}
