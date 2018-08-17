using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Internal.Cryptography.Pal
{
	internal struct CertificateData
	{
		internal struct AlgorithmIdentifier
		{
			internal string AlgorithmId;
			internal byte[] Parameters;
		}

		internal byte[] RawData;
		internal byte[] SubjectPublicKeyInfo;

		internal int Version;
		internal byte[] SerialNumber;
		internal AlgorithmIdentifier TbsSignature;
		internal X500DistinguishedName Issuer;
		internal DateTime NotBefore;
		internal DateTime NotAfter;
		internal X500DistinguishedName Subject;
		internal AlgorithmIdentifier PublicKeyAlgorithm;
		internal byte[] PublicKey;
		internal byte[] IssuerUniqueId;
		internal byte[] SubjectUniqueId;
		internal List<X509Extension> Extensions;
		internal AlgorithmIdentifier SignatureAlgorithm;
		internal byte[] SignatureValue;

		internal CertificateData(byte[] rawData)
		{
			DerSequenceReader reader = new DerSequenceReader(rawData);

			DerSequenceReader tbsCertificate = reader.ReadSequence();

			if (tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag0)
			{
				DerSequenceReader version = tbsCertificate.ReadSequence();
				Version = version.ReadInteger();
			}
			else if (tbsCertificate.PeekTag() != (byte)DerSequenceReader.DerTag.Integer)
			{
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
			}
			else
			{
				Version = 0;
			}

			if (Version < 0 || Version > 2)
				throw new CryptographicException();

			SerialNumber = tbsCertificate.ReadIntegerBytes();

			DerSequenceReader tbsSignature = tbsCertificate.ReadSequence();
			TbsSignature.AlgorithmId = tbsSignature.ReadOidAsString();
			TbsSignature.Parameters = tbsSignature.HasData ? tbsSignature.ReadNextEncodedValue() : Array.Empty<byte>();

			if (tbsSignature.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			Issuer = new X500DistinguishedName(tbsCertificate.ReadNextEncodedValue());

			DerSequenceReader validity = tbsCertificate.ReadSequence();
			NotBefore = validity.ReadX509Date();
			NotAfter = validity.ReadX509Date();

			if (validity.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			Subject = new X500DistinguishedName(tbsCertificate.ReadNextEncodedValue());

			SubjectPublicKeyInfo = tbsCertificate.ReadNextEncodedValue();
			DerSequenceReader subjectPublicKeyInfo = new DerSequenceReader(SubjectPublicKeyInfo);
			DerSequenceReader subjectKeyAlgorithm = subjectPublicKeyInfo.ReadSequence();
			PublicKeyAlgorithm.AlgorithmId = subjectKeyAlgorithm.ReadOidAsString();
			PublicKeyAlgorithm.Parameters = subjectKeyAlgorithm.HasData ? subjectKeyAlgorithm.ReadNextEncodedValue() : Array.Empty<byte>();

			if (subjectKeyAlgorithm.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			PublicKey = subjectPublicKeyInfo.ReadBitString();

			if (subjectPublicKeyInfo.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			if (Version > 0 &&
				tbsCertificate.HasData &&
				tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag1)
			{
				IssuerUniqueId = tbsCertificate.ReadBitString();
			}
			else
			{
				IssuerUniqueId = null;
			}

			if (Version > 0 &&
				tbsCertificate.HasData &&
				tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag2)
			{
				SubjectUniqueId = tbsCertificate.ReadBitString();
			}
			else
			{
				SubjectUniqueId = null;
			}

			Extensions = new List<X509Extension>();

			if (Version > 1 &&
				tbsCertificate.HasData &&
				tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag3)
			{
				DerSequenceReader extensions = tbsCertificate.ReadSequence();
				extensions = extensions.ReadSequence();

				while (extensions.HasData)
				{
					DerSequenceReader extensionReader = extensions.ReadSequence();
					string oid = extensionReader.ReadOidAsString();
					bool critical = false;

					if (extensionReader.PeekTag() == (byte)DerSequenceReader.DerTag.Boolean)
					{
						critical = extensionReader.ReadBoolean();
					}

					byte[] extensionData = extensionReader.ReadOctetString();

					Extensions.Add(new X509Extension(oid, extensionData, critical));

					if (extensionReader.HasData)
						throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
				}
			}

			if (tbsCertificate.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			DerSequenceReader signatureAlgorithm = reader.ReadSequence();
			SignatureAlgorithm.AlgorithmId = signatureAlgorithm.ReadOidAsString();
			SignatureAlgorithm.Parameters = signatureAlgorithm.HasData ? signatureAlgorithm.ReadNextEncodedValue() : Array.Empty<byte>();

			if (signatureAlgorithm.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			SignatureValue = reader.ReadBitString();

			if (reader.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			RawData = rawData;
		}
	}
}