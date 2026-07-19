using IPTranslator.Contracts;
using Newtonsoft.Json;
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
    public class WebApiRequestHandler : IRequestHandler
    {
        public const string jsonMime = "text/json";

        public string ServiceUrl { get; }
        public HttpMessageHandler HttpMessageHandler { get; }
        public bool IsReady { get; private set; }

        public WebApiRequestHandler(string serviceUrl = Constants.ServiceUrl, HttpMessageHandler httpMessageHandler = null)
        {
            ServicePointManager.SecurityProtocol = TlsVersion.Current;

            ServiceUrl = serviceUrl;
            HttpMessageHandler = httpMessageHandler;
            IsReady = true;
        }

        public async Task<Envelope.Response> Send(Envelope.Request requestEnvelope, CancellationToken cancel)
        {
            try
            {
                var jsonRequest = JsonConvert.SerializeObject(requestEnvelope);
                var jsonResponse = await SendJsonRequest(jsonRequest, cancel);
                var responseEnvelope = JsonConvert.DeserializeObject<Envelope.Response>(jsonResponse);
                return responseEnvelope;
            }
            catch (JsonReaderException ex) // indicates block page from firewall
            {
                var uri = new Uri(ServiceUrl);
                var uriTranslate = new Uri(uri, "translate");
                throw new Exception($"Unexpected response from url '{uriTranslate}'. Please, check that your firewall allows access to this url.", ex);
            }
        }

        public async Task<string> SendJsonRequest(string jsonRequest, CancellationToken cancel = default)
        {
            try
            {
                return await SendInternal(jsonRequest, cancel);
            }
            catch (Exception)
            {
                IsReady = false;
                throw;
            }
        }

        private async Task<string> SendInternal(string jsonRequest, CancellationToken cancel)
        {
            ServicePointManager.SecurityProtocol = TlsVersion.Current;

            var uri = new Uri(ServiceUrl);
            var host = uri.Host;
            var httpClient = new HttpClient(HttpMessageHandler ?? new HttpClientHandler(), disposeHandler: false)
            {
                BaseAddress = uri,
                DefaultRequestHeaders =
                {
                    { "Host", host },
                    { "Upgrade-Insecure-Requests", "1" },
                    { "Connection", "Keep-Alive" },
                    { "Cache-Control", "max-age=0" }
                }
            };

            using (httpClient)
            {
                try
                {
                    var request = new HttpRequestMessage(HttpMethod.Post, "translate");
                    request.Content = new StringContent(jsonRequest, Encoding.UTF8, jsonMime);
                    var response = await httpClient.SendAsync(request, cancel);
                    response.EnsureSuccessStatusCode();
                    var jsonResponse = await response.Content.ReadAsStringAsync();
                    return jsonResponse;
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }
    }
}
