using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Internal.Cryptography.Pal
{
	static class AsnReaderExtensions
	{
		public static byte[] ReadBitString(this AsnReader reader)
		{
			reader.TryGetPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> contents);
			return contents.ToArray();
		}

		public static byte[] ReadOctetString(this AsnReader reader)
		{
			reader.TryGetPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> contents);
			return contents.ToArray();
		}
	}

	internal sealed class CertificateDataAsn
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

		static Asn1Tag explicit0 = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
		static Asn1Tag explicit1 = new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);
		static Asn1Tag explicit2 = new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true);
		static Asn1Tag explicit3 = new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true);

		internal CertificateDataAsn(byte[] rawData)
		{
			AsnReader reader = new AsnReader(rawData, AsnEncodingRules.DER).ReadSequence();

			AsnReader tbsCertificate = reader.ReadSequence();

			if (tbsCertificate.PeekTag() == explicit0)
			{
				AsnReader version = tbsCertificate.ReadSequence(explicit0);
				version.TryReadInt32(out Version);
			}
			else if (tbsCertificate.PeekTag() != Asn1Tag.Integer)
			{
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
			}
			else
			{
				Version = 0;
			}

			if (Version < 0 || Version > 2)
				throw new CryptographicException();

			SerialNumber = tbsCertificate.GetIntegerBytes().ToArray();

			AsnReader tbsSignature = tbsCertificate.ReadSequence();
			TbsSignature.AlgorithmId = tbsSignature.ReadObjectIdentifierAsString();
			TbsSignature.Parameters = tbsSignature.HasData ? tbsSignature.GetEncodedValue().ToArray() : Array.Empty<byte>();

			if (tbsSignature.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			Issuer = new X500DistinguishedName(tbsCertificate.GetEncodedValue().ToArray());

			AsnReader validity = tbsCertificate.ReadSequence();
			NotBefore = validity.GetUtcTime().UtcDateTime; // FIXME
			NotAfter = validity.GetUtcTime().UtcDateTime;

			if (validity.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			Subject = new X500DistinguishedName(tbsCertificate.GetEncodedValue().ToArray());

			SubjectPublicKeyInfo = tbsCertificate.GetEncodedValue().ToArray();
			AsnReader subjectPublicKeyInfo = new AsnReader(SubjectPublicKeyInfo, AsnEncodingRules.DER).ReadSequence();
			AsnReader subjectKeyAlgorithm = subjectPublicKeyInfo.ReadSequence();
			PublicKeyAlgorithm.AlgorithmId = subjectKeyAlgorithm.ReadObjectIdentifierAsString();
			PublicKeyAlgorithm.Parameters = subjectKeyAlgorithm.HasData ? subjectKeyAlgorithm.GetEncodedValue().ToArray() : Array.Empty<byte>();

			if (subjectKeyAlgorithm.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			PublicKey = subjectPublicKeyInfo.ReadBitString();

			if (subjectPublicKeyInfo.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			if (Version > 0 &&
				tbsCertificate.HasData &&
				tbsCertificate.PeekTag() == explicit1)
			{
				IssuerUniqueId = tbsCertificate.ReadBitString();
			}
			else
			{
				IssuerUniqueId = null;
			}

			if (Version > 0 &&
				tbsCertificate.HasData &&
				tbsCertificate.PeekTag() == explicit2)
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
				tbsCertificate.PeekTag() == explicit3)
			{
				AsnReader extensions = tbsCertificate.ReadSequence(explicit3);
				extensions = extensions.ReadSequence();

				while (extensions.HasData)
				{
					AsnReader extensionReader = extensions.ReadSequence();
					string oid = extensionReader.ReadObjectIdentifierAsString();
					bool critical = false;

					if (extensionReader.PeekTag() == Asn1Tag.Boolean)
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

			AsnReader signatureAlgorithm = reader.ReadSequence();
			SignatureAlgorithm.AlgorithmId = signatureAlgorithm.ReadObjectIdentifierAsString();
			SignatureAlgorithm.Parameters = signatureAlgorithm.HasData ? signatureAlgorithm.GetEncodedValue().ToArray() : Array.Empty<byte>();

			if (signatureAlgorithm.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			SignatureValue = reader.ReadBitString();

			if (reader.HasData)
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

			RawData = rawData;
		}
	}
}