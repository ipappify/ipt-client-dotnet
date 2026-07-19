using IPTranslator.Contracts;
using System.Threading;
using System.Threading.Tasks;

namespace IPTranslator.Client
{
    public interface IRequestHandler
    {
        Task<Envelope.Response> Send(Envelope.Request requestEnvelope, CancellationToken cancel);
        Task<string> SendJsonRequest(string jsonRequest, CancellationToken cancel = default);
    }
}