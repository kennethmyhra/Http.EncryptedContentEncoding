using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    public class Aes128GcmEncodedStream : Aes128GcmStream
    {
        private readonly SecureRandom _secureRandom = new SecureRandom();
    
        public Aes128GcmEncodedStream(Stream stream, byte[] key, byte[] salt = null, string keyId = null, int recordSize = 4096)
            : base(stream, key, salt, keyId, recordSize)
        {
        }

        public override bool CanRead => _stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _stream.CanWrite;

        public override long Length => _stream.Length;

        public override long Position { get => _stream.Position; set => _stream.Position = value; }

        public override void Flush()
        {
            _stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _stream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            _stream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WriteAsync(buffer, offset, count).Wait();
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0) throw new ArgumentException($"The '{nameof(offset)}' parameter must be a non-negative number.'", nameof(offset));
            if (count < 0) throw new ArgumentException($"The '{nameof(count)}' parameter must be a non-negative number.'", nameof(count));

            CodingHeader codingHeader = new CodingHeader
            {
                Salt = CoalesceSalt(_salt),
                RecordSize = _recordSize,
                KeyId = _keyId
            };

            // PRK = HMAC-SHA-256(salt, IKM)
            byte[] pseudorandomKey = HmacSha256(codingHeader.Salt, _key);
            byte[] contentEncryptionKey = GetContentEncryptionKey(pseudorandomKey);

            await WriteCodingHeaderAsync(_stream, codingHeader).ConfigureAwait(false);

            MemoryStream source = new MemoryStream(buffer);
            await EncryptContentAsync(source, _stream, codingHeader.RecordSize, pseudorandomKey, contentEncryptionKey).ConfigureAwait(false);
        }

        private byte[] CoalesceSalt(byte[] salt)
        {
            if (salt == null)
            {
                salt = new byte[SALT_LENGTH];
                _secureRandom.NextBytes(salt, 0, SALT_LENGTH);
            }
            else if (salt.Length != SALT_LENGTH)
            {
                throw new ArgumentException($" The '{nameof(salt)}' parameter must be {SALT_LENGTH} octets long.", nameof(salt));
            }

            return salt;
        }
                        
        private byte[] GetKeyIdBytes(string keyId)
        {
            byte[] keyIdBytes = String.IsNullOrEmpty(keyId) ? new byte[0] : Encoding.UTF8.GetBytes(keyId);
            if (keyIdBytes.Length > Byte.MaxValue)
            {
                throw new ArgumentException($"The '{nameof(keyId)}' parameter is too long.", nameof(keyId));
            }

            return keyIdBytes;
        }

        private byte[] GetRecordSizeBytes(int recordSize)
        {
            byte[] recordSizeBytes = BitConverter.GetBytes(recordSize);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(recordSizeBytes);
            }

            return recordSizeBytes;
        }

        private async Task WriteCodingHeaderAsync(Stream destination, CodingHeader codingHeader)
        {
            //+----------+---------------+-------------+-----------------+
            //| SALT(16) | RECORDSIZE(4) | KEYIDLEN(1) | KEYID(KEYIDLEN) |
            //+----------+---------------+-------------+-----------------+

            byte[] keyIdBytes = GetKeyIdBytes(codingHeader.KeyId);
            byte[] recordSizeBytes = GetRecordSizeBytes(codingHeader.RecordSize);

            byte[] codingHeaderBytes = new byte[SALT_LENGTH + RECORD_SIZE_LENGTH + KEY_ID_LEN_LENGTH + keyIdBytes.Length];

            codingHeader.Salt.CopyTo(codingHeaderBytes, SALT_INDEX);
            recordSizeBytes.CopyTo(codingHeaderBytes, RECORD_SIZE_INDEX);
            codingHeaderBytes[KEY_ID_LEN_INDEX] = (byte)keyIdBytes.Length;
            keyIdBytes.CopyTo(codingHeaderBytes, KEY_ID_INDEX);

            await destination.WriteAsync(codingHeaderBytes, 0, codingHeaderBytes.Length).ConfigureAwait(false);
        }
                
        private async Task<byte[]> GetPlainTextAsync(Stream source, int recordDataSize, byte? peekedByte)
        {
            int readDataSize;
            byte[] plainText = new byte[recordDataSize + 1];

            if (peekedByte.HasValue)
            {
                plainText[0] = peekedByte.Value;
                readDataSize = (await source.ReadAsync(plainText, 1, recordDataSize - 1).ConfigureAwait(false)) + 1;
            }
            else
            {
                readDataSize = await source.ReadAsync(plainText, 0, recordDataSize).ConfigureAwait(false);
            }

            if (readDataSize == recordDataSize)
            {
                plainText[plainText.Length - 1] = RECORD_DELIMITER;
            }
            else
            {
                Array.Resize(ref plainText, readDataSize + 1);
                plainText[plainText.Length - 1] = LAST_RECORD_DELIMITER;
            }

            return plainText;
        }

        private async Task EncryptContentAsync(Stream source, Stream destination, int recordSize, byte[] pseudorandomKey, byte[] contentEncryptionKey)
        {
            GcmBlockCipher aes128GcmCipher = new GcmBlockCipher(new AesFastEngine());

            ulong recordSequenceNumber = 0;
            int recordDataSize = recordSize - RECORD_OVERHEAD_SIZE;

            byte[] plainText = null;
            int? peekedByte = null;

            do
            {
                plainText = await GetPlainTextAsync(source, recordDataSize, (byte?)peekedByte).ConfigureAwait(false);

                if (plainText[plainText.Length - 1] != 2)
                {
                    peekedByte = source.ReadByte();
                    if (peekedByte == -1)
                    {
                        plainText[plainText.Length - 1] = LAST_RECORD_DELIMITER;
                    }
                }

                ConfigureAes128GcmCipher(aes128GcmCipher, true, pseudorandomKey, contentEncryptionKey, recordSequenceNumber++);
                byte[] cipherText = Aes128GcmCipherProcessBytes(aes128GcmCipher, plainText, plainText.Length);

                await destination.WriteAsync(cipherText, 0, cipherText.Length).ConfigureAwait(false);
            }
            while (plainText[plainText.Length - 1] != LAST_RECORD_DELIMITER);
        }
    }
}
