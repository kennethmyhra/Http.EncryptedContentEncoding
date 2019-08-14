namespace Lib.Net.Http.EncryptedContentEncoding
{
    public class CodingHeader
    {
        public byte[] Salt { get; set; }

        public int RecordSize { get; set; }

        public string KeyId { get; set; }
    }
}
