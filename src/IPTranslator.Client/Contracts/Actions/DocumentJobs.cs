using IPTranslator.Contracts.Messaging;
using System;

namespace IPTranslator.Contracts.Actions
{
    /// <summary>
    /// Batch whole-document translation jobs (asynchronous: create → upload →
    /// submit → poll → fetch). The document itself never travels through the
    /// envelope: <see cref="CreateDocumentJob"/> issues per-job SAS URLs, the
    /// client uploads the <c>iptd-doc:v1</c>-encrypted document directly to blob
    /// storage and embeds the worker-facing URLs (plus the blob key) inside the
    /// end-to-end encrypted job message it submits — the web app relays that
    /// message unopened.
    /// </summary>
    public static class CreateDocumentJob
    {
        public class Request : BaseRequest
        {
            /// <summary>Issue SAS URLs for an optional dictionary file upload
            /// (csv/tsv/xlsx; blob slot 'dict'). Default false = old-client shape.</summary>
            public bool WithDictionary { get; set; }

            /// <summary>How many TMX translation-memory uploads to issue SAS URLs
            /// for (blob slots 'tm0'..; 0–<see cref="DocumentJobLimits.MaxTranslationMemories"/>).
            /// Default 0 = old-client shape.</summary>
            public int TranslationMemoryCount { get; set; }
        }

        public class Response : BaseResponse
        {
            public Guid JobId { get; set; }

            /// <summary>Client-facing SAS (create+write): PUT the encrypted input document here.</summary>
            public string InputUploadUrl { get; set; }

            /// <summary>
            /// Worker-facing SAS URLs. The client copies these VERBATIM into the
            /// encrypted job message (doc_input_url, doc_output_url, doc_status_url,
            /// doc_cancel_url, doc_usage_url) — the worker holds no storage
            /// credentials of its own.
            /// </summary>
            public string WorkerInputUrl { get; set; }
            public string WorkerOutputUrl { get; set; }
            public string WorkerStatusUrl { get; set; }
            public string WorkerCancelUrl { get; set; }
            public string WorkerUsageUrl { get; set; }

            /// <summary>Optional-input SAS URLs, issued only when requested (null
            /// otherwise): the client-facing upload URL and the worker-facing read
            /// URL per file, same copy-verbatim contract as above (doc_dict_url,
            /// doc_tm_urls).</summary>
            public string DictionaryUploadUrl { get; set; }
            public string WorkerDictionaryUrl { get; set; }
            public string[] TranslationMemoryUploadUrls { get; set; }
            public string[] WorkerTranslationMemoryUrls { get; set; }
        }
    }

    public static class SubmitDocumentJob
    {
        public class Request : BaseRequest
        {
            public Guid JobId { get; set; }

            /// <summary>
            /// Informational document metadata for the usage report. The BILLING
            /// identity (document id, key, created) is not client-supplied: the
            /// worker's DocTool reads it from the document's IPTranslator binding
            /// (or mints it) and reports it with the completion — so batch and
            /// add-in translations of the same document dedup against each other.
            /// </summary>
            public string DocumentName { get; set; }
            public string DocumentCustomRef { get; set; }

            /// <summary>The end-to-end encrypted translate_document request; its
            /// request_id must be the JobId ("N" format) so the completion event
            /// can be correlated without opening the message.</summary>
            public TranslatorRequestMessage Message { get; set; }
        }

        public class Response : BaseResponse
        {
            public Guid JobId { get; set; }
        }
    }

    public static class GetDocumentJob
    {
        public class Request : BaseRequest
        {
            public Guid JobId { get; set; }

            /// <summary>Server-side hold in seconds (0–25): the call returns early
            /// on any state or progress change — near-comet latency without
            /// long-lived connections.</summary>
            public int WaitSeconds { get; set; }
        }

        public class Response : BaseResponse
        {
            public Guid JobId { get; set; }

            public DocumentJobStateEnum State { get; set; }
            public DateTimeOffset Created { get; set; }
            public DateTimeOffset? Completed { get; set; }

            /// <summary>Progress from the worker's plaintext status blob (segments done/total).</summary>
            public int ProgressDone { get; set; }
            public int ProgressTotal { get; set; }

            /// <summary>Content-free error code when State == failed.</summary>
            public string ErrorCode { get; set; }

            /// <summary>Billed units from the completion envelope (terminal states only).</summary>
            public int ConsumedUnits { get; set; }

            /// <summary>The document id usage was registered under (done jobs only):
            /// the binding identity from the output document, as reported by the
            /// worker — the same id the add-in will use for this document.</summary>
            public Guid DocumentId { get; set; }

            /// <summary>Read SAS for the encrypted result document (State == done only).</summary>
            public string ResultUrl { get; set; }

            /// <summary>The worker's full response envelope (terminal states only):
            /// the client decrypts the document summary and verifies the billing
            /// fields against the GCM AAD — end to end, like the relay path.</summary>
            public TranslatorResponseMessage Message { get; set; }
        }
    }

    public static class CancelDocumentJob
    {
        public class Request : BaseRequest
        {
            public Guid JobId { get; set; }
        }

        public class Response : BaseResponse
        {
            public Guid JobId { get; set; }

            /// <summary>True when the cancel request reached a non-terminal job
            /// (the worker honors it between segments); false when the job was
            /// already terminal.</summary>
            public bool Cancelling { get; set; }
        }
    }
}
