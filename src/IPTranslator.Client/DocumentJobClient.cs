using IPTranslator.Contracts;
using IPTranslator.Contracts.Actions;
using IPTranslator.Client.E2E;
using IPTranslator.Client.Messaging;
using IPTranslator.Contracts.Messaging;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace IPTranslator.Client
{
    /// <summary>
    /// Client for batch whole-document translation jobs, end-to-end encrypted:
    /// the document is encrypted with a fresh per-job blob key
    /// (<see cref="DocumentBlobCipher"/>, iptd-doc:v1) and uploaded straight to
    /// blob storage; the job message carries the key and the worker-facing SAS
    /// URLs INSIDE its encrypted body, relayed unopened by the web app.
    ///
    /// Session-scoped: results can only be fetched through the same instance
    /// that submitted the job (the response envelope is bound to this session's
    /// message key, and the blob key lives in the returned handle).
    /// </summary>
    public class DocumentJobClient
    {
        private readonly IRequestHandler requestHandler;
        private readonly TranslatorClientMessageHandler messageHandler;
        private readonly HttpMessageHandler blobHttpHandler;
        private readonly string client;
        private readonly string clientVersion;

        /// <param name="servicePublicKeyBase64">The translation service's X-Wing
        /// public key (pinned, or obtained from the Ping response's signed
        /// announcement; see <see cref="Messaging.SignedKeyAnnouncement"/>).</param>
        /// <param name="blobHttpHandler">Transport for the direct blob uploads /
        /// downloads (SAS URLs); tests inject a fake, production uses the default.</param>
        public DocumentJobClient(IRequestHandler requestHandler, string servicePublicKeyBase64,
            HttpMessageHandler blobHttpHandler = null)
        {
            this.requestHandler = requestHandler ?? throw new ArgumentNullException(nameof(requestHandler));
            messageHandler = new TranslatorClientMessageHandler(servicePublicKeyBase64);
            if (!messageHandler.IsEncrypted)
                throw new ArgumentException("Document jobs require the service public key (end-to-end encryption).",
                    nameof(servicePublicKeyBase64));
            this.blobHttpHandler = blobHttpHandler;

            try
            {
                var name = Assembly.GetExecutingAssembly().GetName();
                client = name.Name;
                clientVersion = name.Version.ToString();
            }
            catch (Exception)
            {
            }
        }

        public sealed class DocumentJobHandle
        {
            public Guid JobId { get; internal set; }

            /// <summary>The per-job blob key (the client's own secret; keep it if the
            /// result is to be fetched after this handle would otherwise be lost).</summary>
            public byte[] DocumentKey { get; internal set; }
        }

        public sealed class DocumentJobResult
        {
            /// <summary>The translated document (decrypted .docx bytes).</summary>
            public byte[] Document { get; internal set; }

            /// <summary>The worker's decrypted job summary (verified end-to-end).</summary>
            public DocumentResult Summary { get; internal set; }

            /// <summary>Billed units from the response envelope (GCM-AAD-bound).</summary>
            public int ConsumedUnits { get; internal set; }
        }

        /// <summary>
        /// Creates a job, uploads the encrypted document, and submits the encrypted
        /// job message. Returns the handle for polling / fetching.
        /// <paramref name="documentName"/>/<paramref name="documentCustomRef"/> are
        /// informational (usage report); the BILLING identity (document id, key,
        /// created) is not supplied by the client — the worker's DocTool reads it
        /// from the document's IPTranslator binding (or mints it) and reports it
        /// with the completion, so the hashes and the document id match what the
        /// add-in uses on the same (non-finalized) output document.
        /// <paramref name="dictionary"/> is an optional csv/tsv/xlsx file the worker
        /// imports into the document binding and applies per segment
        /// (<paramref name="dictionaryFormat"/> required with it);
        /// <paramref name="translationMemories"/> are optional TMX files — exact
        /// source matches are applied directly (unbilled), the rest becomes
        /// translation context. Each rides its own encrypted blob under the job key.
        /// </summary>
        public async Task<DocumentJobHandle> Submit(string documentName, byte[] documentBytes,
            string sourceLanguage, string targetLanguage,
            bool finalize = true, string task = null, int? beamWidth = null,
            string documentCustomRef = null,
            byte[] dictionary = null, string dictionaryFormat = null,
            IReadOnlyList<byte[]> translationMemories = null,
            CancellationToken cancel = default)
        {
            if (documentBytes == null || documentBytes.Length == 0)
                throw new ArgumentException("documentBytes required.", nameof(documentBytes));
            if (dictionary != null && Array.IndexOf(DocumentJobLimits.DictionaryFormats, dictionaryFormat) < 0)
                throw new ArgumentException("dictionaryFormat must be csv, tsv or xlsx.", nameof(dictionaryFormat));
            if (dictionary == null && dictionaryFormat != null)
                throw new ArgumentException("dictionaryFormat requires dictionary.", nameof(dictionaryFormat));
            var tmCount = translationMemories?.Count ?? 0;
            if (tmCount > DocumentJobLimits.MaxTranslationMemories)
                throw new ArgumentException(
                    $"At most {DocumentJobLimits.MaxTranslationMemories} translation memories are supported.",
                    nameof(translationMemories));

            // 1. create: job id + SAS URLs (incl. the optional-input slots)
            var createEnvelope = await Send(new Envelope.Request
            {
                CreateDocumentJob = new CreateDocumentJob.Request
                {
                    WithDictionary = dictionary != null,
                    TranslationMemoryCount = tmCount,
                }
            }, cancel);
            var created = createEnvelope.CreateDocumentJob;
            var jobId = created.JobId;
            var jobIdWire = jobId.ToString("N");

            // 2. encrypt + upload the document (direction 'in') and the optional
            // inputs, each sealed under its own AAD slot with the same job key
            var documentKey = DocumentBlobCipher.NewKey();
            var blob = DocumentBlobCipher.Encrypt(documentKey, jobIdWire, DocumentBlobCipher.DirectionIn, documentBytes);
            await UploadBlob(created.InputUploadUrl, blob, cancel);

            if (dictionary != null)
            {
                await UploadBlob(created.DictionaryUploadUrl,
                    DocumentBlobCipher.Encrypt(documentKey, jobIdWire, DocumentBlobCipher.DictionarySlot, dictionary),
                    cancel);
            }
            for (var i = 0; i < tmCount; i++)
            {
                await UploadBlob(created.TranslationMemoryUploadUrls[i],
                    DocumentBlobCipher.Encrypt(documentKey, jobIdWire, DocumentBlobCipher.TranslationMemorySlot(i),
                        translationMemories[i]),
                    cancel);
            }

            // 3. encrypted job message: blob key + worker URLs travel inside the body.
            // scope_key is only the worker's hash-scope FALLBACK — the binding's
            // document key read/minted by DocTool takes precedence.
            var body = new TranslatorRequestBody
            {
                scope_key = jobIdWire,
                type = TranslatorRequestTypeEnum.translate_document,
                task = task ?? "",
                desired_beamwidth = beamWidth,
                src_lang = sourceLanguage,
                trg_lang = targetLanguage,
                src_text = new string[0],
                doc_job_id = jobIdWire,
                doc_input_url = created.WorkerInputUrl,
                doc_output_url = created.WorkerOutputUrl,
                doc_status_url = created.WorkerStatusUrl,
                doc_cancel_url = created.WorkerCancelUrl,
                doc_usage_url = created.WorkerUsageUrl,
                doc_key = documentKey,
                doc_finalize = finalize,
                doc_dict_url = dictionary != null ? created.WorkerDictionaryUrl : null,
                doc_dict_format = dictionary != null ? dictionaryFormat : null,
                doc_tm_urls = tmCount > 0 ? created.WorkerTranslationMemoryUrls : null,
            };
            // correlation contract: request_id == JobId ("N")
            var message = messageHandler.BuildRequest(body, jobIdWire);

            await Send(new Envelope.Request
            {
                SubmitDocumentJob = new SubmitDocumentJob.Request
                {
                    JobId = jobId,
                    DocumentName = documentName,
                    DocumentCustomRef = documentCustomRef,
                    Message = message,
                }
            }, cancel);

            return new DocumentJobHandle { JobId = jobId, DocumentKey = documentKey };
        }

        /// <summary>
        /// Current job state and progress. <paramref name="waitSeconds"/> (0–25) asks
        /// the server to hold the call until something changes — the polling loop
        /// stays responsive without connection-lifetime risk.
        /// </summary>
        public async Task<GetDocumentJob.Response> GetStatus(DocumentJobHandle handle, int waitSeconds = 0,
            CancellationToken cancel = default)
        {
            var envelope = await Send(new Envelope.Request
            {
                GetDocumentJob = new GetDocumentJob.Request { JobId = handle.JobId, WaitSeconds = waitSeconds }
            }, cancel);
            return envelope.GetDocumentJob;
        }

        /// <summary>
        /// Downloads and decrypts the result of a DONE job, decrypts the worker's
        /// job summary from the response envelope, and verifies the id echo.
        /// </summary>
        public async Task<DocumentJobResult> GetResult(DocumentJobHandle handle, CancellationToken cancel = default)
        {
            var status = await GetStatus(handle, 0, cancel);
            if (status.State != DocumentJobStateEnum.done)
                throw new ServiceException(ResponseCode.BadRequest,
                    $"Document job {handle.JobId} is {status.State}, not done" +
                    (string.IsNullOrEmpty(status.ErrorCode) ? "." : $" ({status.ErrorCode})."));
            if (string.IsNullOrEmpty(status.ResultUrl) || status.Message == null)
                throw new ServiceException(ResponseCode.ServiceError, "Job is done but result URL or response message is missing.");

            // end-to-end verification: decrypt the response body with the session
            // key — the GCM AAD binds request_id, consumed_units and object_id
            var (responseBody, requestId) = messageHandler.ParseResponse(status.Message);
            if (!string.Equals(requestId, handle.JobId.ToString("N"), StringComparison.OrdinalIgnoreCase))
                throw new ServiceException(ResponseCode.ServiceError, "Response request id does not match the job.");
            if (responseBody.result_type == TranslatorResultTypeEnum.error)
                throw new ServiceException(ResponseCode.ServiceError, $"Service failed with: {responseBody.error_details}");

            var encrypted = await DownloadBlob(status.ResultUrl, cancel);
            var document = DocumentBlobCipher.Decrypt(handle.DocumentKey, handle.JobId.ToString("N"),
                DocumentBlobCipher.DirectionOut, encrypted);

            return new DocumentJobResult
            {
                Document = document,
                Summary = responseBody.document,
                ConsumedUnits = status.Message.consumed_units,
            };
        }

        /// <summary>Requests cancellation; true when the job was still cancellable.</summary>
        public async Task<bool> Cancel(DocumentJobHandle handle, CancellationToken cancel = default)
        {
            var envelope = await Send(new Envelope.Request
            {
                CancelDocumentJob = new CancelDocumentJob.Request { JobId = handle.JobId }
            }, cancel);
            return envelope.CancelDocumentJob.Cancelling;
        }

        // ---------- internals ----------

        private async Task<Envelope.Response> Send(Envelope.Request request, CancellationToken cancel)
        {
            request.Client = client;
            request.ClientVersion = clientVersion;
            var response = await requestHandler.Send(request, cancel);
            ManagementClient.ThrowOnError(response);
            return response;
        }

        private HttpClient CreateBlobClient()
        {
            return blobHttpHandler != null
                ? new HttpClient(blobHttpHandler, disposeHandler: false)
                : new HttpClient();
        }

        private async Task UploadBlob(string sasUrl, byte[] data, CancellationToken cancel)
        {
            using (var http = CreateBlobClient())
            using (var content = new ByteArrayContent(data))
            {
                var request = new HttpRequestMessage(HttpMethod.Put, sasUrl) { Content = content };
                request.Headers.Add("x-ms-blob-type", "BlockBlob");
                var response = await http.SendAsync(request, cancel);
                response.EnsureSuccessStatusCode();
            }
        }

        private async Task<byte[]> DownloadBlob(string sasUrl, CancellationToken cancel)
        {
            using (var http = CreateBlobClient())
            {
                var response = await http.GetAsync(sasUrl, cancel);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsByteArrayAsync();
            }
        }
    }
}
