using IPTranslator.Contracts.Actions;
using System.Threading;
using System.Threading.Tasks;

namespace IPTranslator.Client
{
    /// <summary>
    /// Content-free management API of the translator service. These actions
    /// never carry document content, so they are not end-to-end encrypted.
    /// This public client only carries Ping (connectivity check and the
    /// announcement channel for the service's end-to-end encryption key).
    /// </summary>
    public interface IManagementClient
    {
        Task<Ping.Response> Ping(Ping.Request request, CancellationToken cancel = default);
        Task<bool> TestConnection(int timeout);
    }
}
