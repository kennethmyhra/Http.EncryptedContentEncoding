using Lib.Net.Http.EncryptedContentEncoding;
using System;
using System.Collections.Generic;
using System.Web.Http;

namespace Server
{
    public static class WebApiConfig
    {
        private static IDictionary<string, byte[]> _keys = new Dictionary<string, byte[]>
                {
                    { string.Empty, Convert.FromBase64String("yqdlZ+tYemfogSmv7Ws5PQ==") },
                    { "a1", Convert.FromBase64String("BO3ZVPxUlnLORbVGMpbT1Q==") }
                };
        private static Func<string, byte[]> _keyLocator = (keyId) => _keys[keyId ?? String.Empty];

        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            config.MessageHandlers.Add(new Aes128GcmEncodingHandler(_keyLocator));

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
