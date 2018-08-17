using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace System.Security.Cryptography.Asn1
{
	internal static class AsnReaderExtensions
	{
		public static long ReadInt64(this AsnReader reader)
		{
			if (reader.TryReadInt64(out long value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static ulong ReadUInt64(this AsnReader reader)
		{
			if (reader.TryReadUInt64(out ulong value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static int ReadInt32(this AsnReader reader)
		{
			if (reader.TryReadInt32(out int value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static uint ReadUInt32(this AsnReader reader)
		{
			if (reader.TryReadUInt32(out uint value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static short ReadInt16(this AsnReader reader)
		{
			if (reader.TryReadInt16(out short value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static ushort ReadUInt16(this AsnReader reader)
		{
			if (reader.TryReadUInt16(out ushort value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static sbyte ReadInt8(this AsnReader reader)
		{
			if (reader.TryReadInt8(out sbyte value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static byte ReadUInt8(this AsnReader reader)
		{
			if (reader.TryReadUInt8(out byte value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static long ReadInt64(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadInt64(tag, out long value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static ulong ReadUInt64(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadUInt64(tag, out ulong value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static int ReadInt32(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadInt32(tag, out int value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static uint ReadUInt32(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadUInt32(tag, out uint value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static short ReadInt16(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadInt16(tag, out short value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static ushort ReadUInt16(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadUInt16(tag, out ushort value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static sbyte ReadInt8(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadInt8(tag, out sbyte value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static byte ReadUInt8(this AsnReader reader, Asn1Tag tag)
		{
			if (reader.TryReadUInt8(tag, out byte value))
				return value;
			throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
		}

		public static ReadOnlyMemory<byte> GetEncodedValue(this AsnReader reader, Asn1Tag matchTag)
		{
			Asn1Tag nextTag = reader.PeekTag();

			if (matchTag.TagClass != nextTag.TagClass ||
				matchTag.TagValue != nextTag.TagValue)
			{
				throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
			}

			return reader.GetEncodedValue();
		}

		public static ReadOnlyMemory<byte> GetBitStringBytes(this AsnReader reader, Asn1Tag expectedTag)
		{
			if (reader.TryGetPrimitiveBitStringValue(expectedTag, out _, out ReadOnlyMemory<byte> contents))
			{
				return contents;
			}

			// Guaranteed too big, because it has the tag and length.
			int length = reader.PeekEncodedValue().Length;
			byte[] rented = ArrayPool<byte>.Shared.Rent(length);

			try
			{
				if (reader.TryCopyBitStringBytes(expectedTag, rented, out _, out int bytesWritten))
				{
					return new ReadOnlyMemory<byte>(rented.AsSpan(0, bytesWritten).ToArray());
				}

				Debug.Fail("TryCopyBitStringBytes produced more data than the encoded size");
				throw new CryptographicException();
			}
			finally
			{
				Array.Clear(rented, 0, length);
				ArrayPool<byte>.Shared.Return(rented);
			}
		}

		public static ReadOnlyMemory<byte> GetOctetStringBytes(this AsnReader reader, Asn1Tag expectedTag)
		{
			if (reader.TryGetPrimitiveOctetStringBytes(expectedTag, out ReadOnlyMemory<byte> contents))
			{
				return contents;
			}

			// Guaranteed too big, because it has the tag and length.
			int length = reader.PeekEncodedValue().Length;
			byte[] rented = ArrayPool<byte>.Shared.Rent(length);

			try
			{
				if (reader.TryCopyOctetStringBytes(expectedTag, rented, out int bytesWritten))
				{
					return new ReadOnlyMemory<byte>(rented.AsSpan(0, bytesWritten).ToArray());
				}

				Debug.Fail("TryCopyOctetStringBytes produced more data than the encoded size");
				throw new CryptographicException();
			}
			finally
			{
				Array.Clear(rented, 0, length);
				ArrayPool<byte>.Shared.Return(rented);
			}
		}
	}
}
