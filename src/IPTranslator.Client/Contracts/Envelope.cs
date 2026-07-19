using IPTranslator.Contracts.Actions;
using System;

namespace IPTranslator.Contracts
{
    /// <summary>
    /// The plaintext transport envelope of the web API (one action per request).
    /// This public client only carries the actions it needs: Ping and the
    /// document-job actions; the full service envelope has more, which a
    /// response may include and this client ignores.
    /// </summary>
    public class Envelope
    {
        public class Request
        {
            public Guid CorrelationId { get; set; } = Guid.NewGuid();
            public string Client { get; set; }
            public string ClientVersion { get; set; }

            public CreateDocumentJob.Request CreateDocumentJob { get; set; }
            public SubmitDocumentJob.Request SubmitDocumentJob { get; set; }
            public GetDocumentJob.Request GetDocumentJob { get; set; }
            public CancelDocumentJob.Request CancelDocumentJob { get; set; }

            public Ping.Request Ping { get; set; }
        }

        public class Response
        {
            public Guid CorrelationId { get; set; }

            public ResponseCode Code { get; set; } = ResponseCode.OK;
            public string Message { get; set; }
            /// <summary>
            /// Uri to open for resolving an issue - or at least get more information on the issue.
            /// </summary>
            public string ResolveErrorUri { get; set; }

            public CreateDocumentJob.Response CreateDocumentJob { get; set; }
            public SubmitDocumentJob.Response SubmitDocumentJob { get; set; }
            public GetDocumentJob.Response GetDocumentJob { get; set; }
            public CancelDocumentJob.Response CancelDocumentJob { get; set; }

            public Ping.Response Ping { get; set; }

            public Guid InstanceId { get; set; }
            public double ComputeTimeSec { get; set; }
            public double TripTimeSec { get; set; }
        }
    }
}
