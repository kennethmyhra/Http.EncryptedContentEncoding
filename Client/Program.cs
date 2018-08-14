using Lib.Net.Http.EncryptedContentEncoding;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Http.EncryptedContentEncoding.Client
{
    class Program
    {
        private static IDictionary<string, byte[]> _keys = new Dictionary<string, byte[]>
            {
                { "a1", Convert.FromBase64String("BO3ZVPxUlnLORbVGMpbT1Q==") }
            };
        private static Func<string, byte[]> _keyLocator = (keyId) => _keys[keyId ?? String.Empty];

        private const string URL_BASE = "http://localhost:58022/";

        static void Main(string[] args)
        {
            RunHttpGetEncryptedContentExample(Console.Out);
            Console.WriteLine();

            RunHttpPostEncryptedContentAndReceiveEncryptedContentExample(Console.Out);
            Console.WriteLine();

            Console.WriteLine("Press any key to continue. . .");
            Console.ReadKey(true);
        }

        private static void RunHttpPostEncryptedContentAndReceiveEncryptedContentExample(TextWriter output)
        {
            string data = "{ \"Content\": \"Hello world from the client\"";
            string contentType = "application/json";
            HttpResponseMessage response = HttpPostEncryptedContentAndReceiveEncryptedResponse("a1", $"{URL_BASE}api/HelloWorld", data, contentType);
            output.WriteLine($"{(int)response.StatusCode} {response.StatusCode} - {response.RequestMessage.Method} {response.RequestMessage.RequestUri.AbsoluteUri}");
            if(response.IsSuccessStatusCode)
            {
                output.WriteLine($"Encrypted content: {response.Content.ReadAsStringAsync().GetAwaiter().GetResult()}");
                if (response.Content.Headers.ContentEncoding.Contains("aes128gcm"))
                {
                    response.Content = new Aes128GcmDecodedContent(response.Content, _keyLocator);
                    output.WriteLine($"Decrypted content: {response.Content.ReadAsStringAsync().GetAwaiter().GetResult()}");
                }
            }

        }

        private static void RunHttpGetEncryptedContentExample(TextWriter output)
        {
            HttpResponseMessage response = HttpGetEncryptedResponse("a1", $"{URL_BASE}api/HelloWorld");
            output.WriteLine($"{(int)response.StatusCode} {response.StatusCode} - {response.RequestMessage.Method} {response.RequestMessage.RequestUri.AbsoluteUri}");
            if (response.IsSuccessStatusCode)
            {
                output.WriteLine($"Encrypted content: {response.Content.ReadAsStringAsync().GetAwaiter().GetResult()}");
                if (response.Content.Headers.ContentEncoding.Contains("aes128gcm"))
                {
                    response.Content = new Aes128GcmDecodedContent(response.Content, _keyLocator);
                    output.WriteLine($"Decrypted content: {response.Content.ReadAsStringAsync().GetAwaiter().GetResult()}");
                }
            }
        }
        
        private static HttpResponseMessage HttpPostEncryptedContentAndReceiveEncryptedResponse(string keyId, string url, string data, string contentType)
        {
            return HttpPostEncryptedContentAndReceiveEncryptedResponseAsync(keyId, url, data, contentType).GetAwaiter().GetResult();
        }

        private static async Task<HttpResponseMessage> HttpPostEncryptedContentAndReceiveEncryptedResponseAsync(string keyId, string url, string data, string contentType)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpContent content = new StringContent(data);
                byte[] key = _keyLocator(keyId);
                HttpContent encryptedContent = new Aes128GcmEncodedContent(content, key, keyId, 4096);

                client.DefaultRequestHeaders.Add("X-aes128gcm-KeyId", keyId);
                client.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("aes128gcm"));
                content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
                
                return await client.PostAsync(url, content);
            }
        }

        private static HttpResponseMessage HttpGetEncryptedResponse(string keyId, string url)
        {
            return HttpGetEncryptedResponseAsync(keyId, url).GetAwaiter().GetResult();
        }

        private static async Task<HttpResponseMessage> HttpGetEncryptedResponseAsync(string keyId, string url)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("aes128gcm"));
                client.DefaultRequestHeaders.Add("X-aes128gcm-KeyId", keyId);
                return await client.GetAsync(url);
            }
        }
    }
}
