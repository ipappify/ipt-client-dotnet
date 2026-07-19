using IPTranslator.Contracts;
using IPTranslator.Contracts.Actions;
using Serilog;
using System;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace IPTranslator.Client
{
    /// <summary>
    /// Client for the content-free management actions of the translator web API.
    /// This public client only carries Ping (connectivity check and the signed
    /// announcement channel for the service's end-to-end encryption key); the
    /// document jobs go through <see cref="DocumentJobClient"/>, which relays
    /// their content end-to-end encrypted. Also hosts the plaintext envelope
    /// transport that the other clients build on.
    /// </summary>
    public class ManagementClient : IManagementClient
    {
        public IRequestHandler RequestHandler { get; }
        public string Client { get; set; }
        public string ClientVersion { get; set; }

        public ManagementClient(IRequestHandler requestHandler)
        {
            RequestHandler = requestHandler;

            try
            {
                var name = Assembly.GetExecutingAssembly().GetName();
                Client = name.Name;
                ClientVersion = name.Version.ToString();
            }
            catch (Exception)
            {
            }
        }

        public ManagementClient(string serviceUrl = Constants.ServiceUrl, HttpMessageHandler httpMessageHandler = null) :
            this(new WebApiRequestHandler(serviceUrl, httpMessageHandler)) { }

        public async Task<Ping.Response> Ping(Ping.Request request, CancellationToken cancel = default)
        {
            return (await Send(nameof(Ping), new Envelope.Request { Ping = request }, cancel)).Ping;
        }

        public async Task<bool> TestConnection(int timeout)
        {
            try
            {
                var cancel = new CancellationTokenSource(timeout).Token;
                await Ping(new Ping.Request(), cancel);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Stamps the client identification onto the envelope, sends it, and
        /// translates error response codes into exceptions.
        /// </summary>
        internal async Task<Envelope.Response> Send(string action, Envelope.Request requestEnvelope, CancellationToken cancel)
        {
            Log.Information("Request {Action}.", action);

            requestEnvelope.Client = Client;
            requestEnvelope.ClientVersion = ClientVersion;
            var responseEnvelope = await RequestHandler.Send(requestEnvelope, cancel);
            Log.Information("Response to {Action} {@Code}, {@ComputeTimeSec}, {@TripTimeSec}", action, responseEnvelope.Code, responseEnvelope.ComputeTimeSec, responseEnvelope.TripTimeSec);
            ThrowOnError(responseEnvelope);
            return responseEnvelope;
        }

        internal static void ThrowOnError(Envelope.Response responseEnvelope)
        {
            switch (responseEnvelope.Code)
            {
                case ResponseCode.OK:
                    break;

                case ResponseCode.Canceled:
                    throw new OperationCanceledException(responseEnvelope.Message);

                case ResponseCode.QuotaExceeded:
                    throw new QuotaExceededException(responseEnvelope.Message, responseEnvelope.ResolveErrorUri);

                default:
                    throw new ServiceException(responseEnvelope.Code, responseEnvelope.Message);
            }
        }
    }
}
