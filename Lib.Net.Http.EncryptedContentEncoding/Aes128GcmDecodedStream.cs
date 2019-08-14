using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    public class Aes128GcmDecodedStream : Aes128GcmStream
    {
        private long _internalPosition = 0;

        public Aes128GcmDecodedStream(Stream stream, byte[] key, byte[] salt = null, string keyId = null, int recordSize = 4096)
            : base(stream, key, salt, keyId, recordSize)
        {
        }

        public override bool CanRead => _stream.CanRead;

        public override bool CanSeek => _stream.CanSeek;

        public override bool CanWrite => false;

        public override long Length => _stream.Length;

        public override long Position { get => _stream.Position; set => _stream.Position = value; }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Task<int> task = ReadAsync(buffer, offset, count);
            task.Wait();
            return task.Result;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            long beginPosition = _internalPosition;
            if (CodingHeader == null)
            {
                CodingHeader = await ReadCodingHeaderAsync(_stream);
            }

            byte[] pseudorandomKey = HmacSha256(CodingHeader.Salt, _key);
            byte[] contentEncryptionKey = GetContentEncryptionKey(pseudorandomKey);

            MemoryStream stream = new MemoryStream(buffer);
            await DecryptContentAsync(_stream, stream, CodingHeader.RecordSize, pseudorandomKey, contentEncryptionKey).ConfigureAwait(false);

            long endPosition = _internalPosition;
            
            if ((endPosition - beginPosition) < count)
                return 0;
            else
                return (int)(endPosition - beginPosition);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _stream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        private static void ThrowInvalidCodingHeaderException()
        {
            throw new FormatException("Invalid coding header.");
        }

        private static void ThrowInvalidOrderOrMissingRecordException()
        {
            throw new FormatException("Invalid records order or missing record(s).");
        }

        private async Task<byte[]> ReadCodingHeaderBytesAsync(Stream source, int count)
        {
            byte[] bytes = new byte[count];
            int bytesRead = await source.ReadAsync(bytes, 0, count).ConfigureAwait(false);
            if (bytesRead != count)
            {
                ThrowInvalidCodingHeaderException();
            }

            return bytes;
        }

        private async Task<int> ReadRecordSizeAsync(Stream source)
        {
            byte[] recordSizeBytes = await ReadCodingHeaderBytesAsync(source, RECORD_SIZE_LENGTH).ConfigureAwait(false);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(recordSizeBytes);
            }
            uint recordSize = BitConverter.ToUInt32(recordSizeBytes, 0);

            if (recordSize > Int32.MaxValue)
            {
                throw new NotSupportedException($"This implementation doesn't support record size larger than {Int32.MaxValue}.");
            }

            return (int)recordSize;
        }

        private async Task<string> ReadKeyId(Stream source)
        {
            string keyId = null;

            int keyIdLength = source.ReadByte();

            if (keyIdLength == -1)
            {
                ThrowInvalidCodingHeaderException();
            }

            if (keyIdLength > 0)
            {
                byte[] keyIdBytes = await ReadCodingHeaderBytesAsync(source, keyIdLength).ConfigureAwait(false);
                keyId = Encoding.UTF8.GetString(keyIdBytes);
            }

            return keyId;
        }

        private async Task<CodingHeader> ReadCodingHeaderAsync(Stream source)
        {
            return new CodingHeader
            {
                Salt = await ReadCodingHeaderBytesAsync(source, SALT_LENGTH).ConfigureAwait(false),
                RecordSize = await ReadRecordSizeAsync(source).ConfigureAwait(false),
                KeyId = await ReadKeyId(source).ConfigureAwait(false)
            };
        }
        
        private static int GetRecordDelimiterIndex(byte[] plainText, int recordDataSize)
        {
            int recordDelimiterIndex = -1;
            for (int plaintTextIndex = plainText.Length - 1; plaintTextIndex >= 0; plaintTextIndex--)
            {
                if (plainText[plaintTextIndex] == 0)
                {
                    continue;
                }

                if ((plainText[plaintTextIndex] == RECORD_DELIMITER) || (plainText[plaintTextIndex] == LAST_RECORD_DELIMITER))
                {
                    recordDelimiterIndex = plaintTextIndex;
                }

                break;
            }

            if ((recordDelimiterIndex == -1) || ((plainText[recordDelimiterIndex] == RECORD_DELIMITER) && ((plainText.Length - 1) != recordDataSize)))
            {
                throw new FormatException("Invalid record delimiter.");
            }

            return recordDelimiterIndex;
        }

        private async Task DecryptContentAsync(Stream source, Stream destination, int recordSize, byte[] pseudorandomKey, byte[] contentEncryptionKey)
        {
            GcmBlockCipher aes128GcmCipher = new GcmBlockCipher(new AesFastEngine());

            ulong recordSequenceNumber = 0;

            byte[] cipherText = new byte[recordSize];
            byte[] plainText = null;
            int recordDataSize = recordSize - RECORD_OVERHEAD_SIZE;
            int recordDelimiterIndex = 0;

            do
            {
                int cipherTextLength = await source.ReadAsync(cipherText, 0, cipherText.Length).ConfigureAwait(false);
                _internalPosition += cipherTextLength;

                if (cipherTextLength == 0)
                {
                    ThrowInvalidOrderOrMissingRecordException();
                }

                ConfigureAes128GcmCipher(aes128GcmCipher, false, pseudorandomKey, contentEncryptionKey, recordSequenceNumber++);
                plainText = Aes128GcmCipherProcessBytes(aes128GcmCipher, cipherText, cipherTextLength);
                recordDelimiterIndex = GetRecordDelimiterIndex(plainText, recordDataSize);

                if ((plainText[recordDelimiterIndex] == LAST_RECORD_DELIMITER) && (source.ReadByte() != -1))
                {
                    ThrowInvalidOrderOrMissingRecordException();
                }

                await destination.WriteAsync(plainText, 0, recordDelimiterIndex).ConfigureAwait(false);
            }
            while (plainText[recordDelimiterIndex] != LAST_RECORD_DELIMITER);
        }
    }
}
