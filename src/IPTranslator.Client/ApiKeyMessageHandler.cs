using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IPTranslator.Client
{
    public class ApiKeyMessageHandler : DelegatingHandler
    {
        public string ApiKey { get; }

        public ApiKeyMessageHandler(string apiKey) : base(new HttpClientHandler())
        {
            ApiKey = apiKey;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ServicePointManager.SecurityProtocol = TlsVersion.Current;

            request.Headers.Authorization = new AuthenticationHeaderValue("ApiKey", ApiKey);
            return await base.SendAsync(request, cancellationToken);
        }
    }
}
