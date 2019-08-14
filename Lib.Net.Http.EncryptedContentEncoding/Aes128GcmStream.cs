using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    public abstract class Aes128GcmStream : Stream
    {
        protected Stream _stream;
        protected byte[] _key;
        protected byte[] _salt;
        protected string _keyId;
        protected int _recordSize;

        protected readonly byte[] _contentEncryptionKeyInfoParameter;
        protected readonly byte[] _nonceInfoParameter;

        protected const int KEY_LENGTH = 16;

        protected const int SALT_INDEX = 0;
        protected const int SALT_LENGTH = 16;

        protected const int RECORD_OVERHEAD_SIZE = 17;
        protected const int MIN_RECORD_SIZE = RECORD_OVERHEAD_SIZE + 1;
        protected const int RECORD_SIZE_INDEX = SALT_INDEX + SALT_LENGTH;
        protected const int RECORD_SIZE_LENGTH = 4;

        protected const int KEY_ID_LEN_INDEX = RECORD_SIZE_INDEX + RECORD_SIZE_LENGTH;
        protected const int KEY_ID_LEN_LENGTH = 1;

        protected const int KEY_ID_INDEX = KEY_ID_LEN_INDEX + KEY_ID_LEN_LENGTH;

        protected const byte INFO_PARAMETER_DELIMITER = 1;

        protected const byte RECORD_DELIMITER = 1;
        protected const byte LAST_RECORD_DELIMITER = 2;


        protected const string CONTENT_ENCRYPTION_KEY_INFO_PARAMETER_STRING = "Content-Encoding: aes128gcm";
        protected const int CONTENT_ENCRYPTION_KEY_LENGTH = 16;

        protected const string NONCE_INFO_PARAMETER_STRING = "Content-Encoding: nonce";
        protected const int NONCE_LENGTH = 12;

        protected Aes128GcmStream(Stream stream, byte[] key, byte[] salt, string keyId, int recordSize = 4096)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            ValidateEncodeParameters(key, recordSize);

            _stream = stream;
            _key = key;
            _keyId = keyId == null ? string.Empty : keyId;
            _recordSize = recordSize;

            // CEK_INFO = "Content-Encoding: aes128gcm" || 0x00 || 0x01
            _contentEncryptionKeyInfoParameter = GetInfoParameter(CONTENT_ENCRYPTION_KEY_INFO_PARAMETER_STRING);

            // NONCE_INFO = "Content-Encoding: nonce" || 0x00 || 0x01
            _nonceInfoParameter = GetInfoParameter(NONCE_INFO_PARAMETER_STRING);
        }
        
        public CodingHeader CodingHeader { get; protected set; }

        private void ValidateEncodeParameters(byte[] key, int recordSize)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length != KEY_LENGTH)
            {
                throw new ArgumentException($" The '{nameof(key)}' parameter must be {KEY_LENGTH} octets long.", nameof(key));
            }

            if (recordSize < MIN_RECORD_SIZE)
            {
                throw new ArgumentException($" The '{nameof(recordSize)}' parameter must be at least {MIN_RECORD_SIZE}.", nameof(recordSize));
            }
        }
        
        private byte[] GetInfoParameter(string infoParameterString)
        {
            byte[] infoParameter = new byte[infoParameterString.Length + 2];

            Encoding.ASCII.GetBytes(infoParameterString, 0, infoParameterString.Length, infoParameter, 0);

            infoParameter[infoParameter.Length - 1] = INFO_PARAMETER_DELIMITER;

            return infoParameter;
        }

        private byte[] GetNonce(byte[] pseudorandomKey, ulong recordSequenceNumber)
        {
            // NONCE = FIRST 12 OCTETS OF HMAC-SHA-256(PRK, NONCE_INFO) XOR SEQ
            byte[] nonce = HmacSha256(pseudorandomKey, _nonceInfoParameter);
            Array.Resize(ref nonce, NONCE_LENGTH);

            byte[] recordSequenceNumberBytes = BitConverter.GetBytes(recordSequenceNumber);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(recordSequenceNumberBytes);
            }
            int leadingNullBytesCount = NONCE_LENGTH - recordSequenceNumberBytes.Length;

            for (int i = 0; i < leadingNullBytesCount; i++)
            {
                nonce[i] = (byte)(nonce[i] ^ 0);
            }

            for (int i = 0; i < recordSequenceNumberBytes.Length; i++)
            {
                nonce[leadingNullBytesCount + i] = (byte)(nonce[leadingNullBytesCount + i] ^ recordSequenceNumberBytes[i]);
            }

            return nonce;
        }

        protected byte[] HmacSha256(byte[] key, byte[] value)
        {
            byte[] hash = null;

            using (HMACSHA256 hasher = new HMACSHA256(key))
            {
                hash = hasher.ComputeHash(value);
            }

            return hash;
        }

        protected byte[] GetContentEncryptionKey(byte[] pseudorandomKey)
        {
            // CEK = FIRST 16 OCTETS OF HMAC-SHA-256(PRK, CEK_INFO)
            byte[] contentEncryptionKey = HmacSha256(pseudorandomKey, _contentEncryptionKeyInfoParameter);
            Array.Resize(ref contentEncryptionKey, CONTENT_ENCRYPTION_KEY_LENGTH);

            return contentEncryptionKey;
        }
        
        protected void ConfigureAes128GcmCipher(GcmBlockCipher aes128GcmCipher, bool forEncryption, byte[] pseudorandomKey, byte[] contentEncryptionKey, ulong recordSequenceNumber)
        {
            aes128GcmCipher.Reset();
            AeadParameters aes128GcmParameters = new AeadParameters(new KeyParameter(contentEncryptionKey), 128, GetNonce(pseudorandomKey, recordSequenceNumber));
            aes128GcmCipher.Init(forEncryption, aes128GcmParameters);
        }

        protected byte[] Aes128GcmCipherProcessBytes(GcmBlockCipher aes128GcmCipher, byte[] bytes, int bytesToProcessLength)
        {
            byte[] processedBytes = new byte[aes128GcmCipher.GetOutputSize(bytesToProcessLength)];
            int lenght = aes128GcmCipher.ProcessBytes(bytes, 0, bytesToProcessLength, processedBytes, 0);
            aes128GcmCipher.DoFinal(processedBytes, lenght);

            return processedBytes;
        }
    }
}
