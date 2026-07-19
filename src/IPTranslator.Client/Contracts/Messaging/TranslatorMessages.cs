using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace IPTranslator.Contracts.Messaging
{
    // All enums in this file serialize as their member names (never ordinals): the
    // names are the wire contract mirrored by the service (strict str enums),
    // and request_type is bound into the response AAD. The [JsonConverter] attributes
    // make this hold on every Newtonsoft path regardless of serializer settings.

    // The service's full request/response bodies have more request types and
    // fields than this public client uses; the trimmed classes below keep the
    // document-job subset (unknown members are ignored on deserialization, and
    // omitted nullable members are never serialized).

    [JsonConverter(typeof(StringEnumConverter))]
    public enum TranslatorRequestTypeEnum
    {
        // translation
        translate,
        translate_align,
        translate_document, // batch whole-document job (dedicated batch workers only)
        // alignment
        align,
        // scoring / embedding / editing
        evaluate,
        embed,
        replace,
        // diagnostics
        probe,
        unreadable
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum TranslatorResultTypeEnum
    {
        // translation
        translations_top_k,
        translations_segments, // replace request will also use this
        translation_alignment,
        document, // summary result of a translate_document job
        // alignment
        alignments,
        // scoring / embedding
        evaluations,
        embeddings,
        // diagnostics
        status,
        error
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum DocumentJobStateEnum
    {
        queued,
        running,
        done,
        failed,
        cancelled
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum StopReasonEnum
    {
        max_len,
        stop_condition
    }

    public class Translation
    {
        public float score { get; set; }
        public string text { get; set; }
        public string lang { get; set; }
        public (int start, int length)[] ranges { get; set; }
        public float[] logits { get; set; }
        public StopReasonEnum? stop_reason { get; set; }
    }

    /// <summary>
    /// Summary of a translate_document job (encrypted response body). Per-segment
    /// content stays inside the output blob; this only carries counts and state.
    /// </summary>
    public class DocumentResult
    {
        public string job_id { get; set; }
        public DocumentJobStateEnum state { get; set; }
        public int total { get; set; }      // segments in the document
        public int translated { get; set; } // segments translated by this job (incl. tm_translated)
        public int failed { get; set; }     // segments that failed individually (job still completes)
        public int tm_translated { get; set; } // of translated: applied from an exact TM match (unbilled)
    }

    /// <summary>
    /// Limits for the optional translate_document job inputs. Mirror of the
    /// corresponding constants in the service's message contract.
    /// </summary>
    public static class DocumentJobLimits
    {
        public const int MaxTranslationMemories = 16;
        public static readonly string[] DictionaryFormats = { "csv", "tsv", "xlsx" };
    }

    /// <summary>
    /// The content-free progress blob the worker overwrites at doc_status_url while
    /// a job runs (plaintext — must never carry document content).
    /// </summary>
    public class DocumentJobStatus
    {
        public int v { get; set; } = 1;
        public DocumentJobStateEnum state { get; set; }
        public int done { get; set; }
        public int total { get; set; }
        public string error_code { get; set; } // nullable
    }

    /// <summary>
    /// Billing record of one translated segment of a document job — the same
    /// (active_hash, count_units) a separate translate request would have produced.
    /// </summary>
    public class DocumentUsageItem
    {
        public byte[] object_id { get; set; }
        public int units { get; set; }
        public float time_ms { get; set; }
    }

    /// <summary>
    /// The plaintext per-segment usage blob the worker uploads to doc_usage_url when
    /// a job completes (content-free: hashes, counts and the document GUID). Items
    /// are in document order, so the envelope totals are verifiable against it:
    /// sum(units) == consumed_units and SHA-256 over the concatenated object_ids ==
    /// the envelope object_id. document_id/document_created are the binding identity
    /// the worker read from (or minted into) the document — usage registers under
    /// them, so it dedups against interactive translations of the same document.
    /// The binding's document KEY stays inside the worker (only hashes derived from
    /// it appear here).
    /// </summary>
    public class DocumentJobUsage
    {
        public int v { get; set; } = 1;
        public string document_id { get; set; } // nullable
        public DateTimeOffset? document_created { get; set; } // nullable
        public DocumentUsageItem[] items { get; set; }
    }

    public class TranslatorRequestBody
    {
        public string scope_key { get; set; }
        public TranslatorRequestTypeEnum type { get; set; }
        public string task { get; set; } // nullable
        public int? desired_beamwidth { get; set; } // nullable
        public string src_lang { get; set; }
        public string trg_lang { get; set; } // nullable
        public string[] src_text { get; set; }
        public string[] trg_text { get; set; } // nullable
        // translate_document job fields (src_text is [] for document jobs; the document
        // lives in blob storage — claim-check pattern). The SAS URLs are scoped to this
        // job; the worker needs no storage credentials of its own.
        public string doc_job_id { get; set; } // nullable
        public string doc_input_url { get; set; } // nullable; SAS, read: encrypted input document (iptd-doc:v1, direction 'in')
        public string doc_output_url { get; set; } // nullable; SAS, create+write: encrypted result (direction 'out')
        public string doc_status_url { get; set; } // nullable; SAS, create+write: DocumentJobStatus json (plaintext, content-free)
        public string doc_cancel_url { get; set; } // nullable; SAS, read: blob existence = cancel requested
        public string doc_usage_url { get; set; } // nullable; SAS, create+write: DocumentJobUsage json (plaintext, content-free)
        public byte[] doc_key { get; set; } // nullable; 32-byte blob key; confidential — only ever inside the encrypted body
        public bool? doc_finalize { get; set; } // nullable; unwrap segment controls + drop binding in the result
        public string doc_dict_url { get; set; } // nullable; SAS, read: encrypted dictionary file (slot 'dict'), optional
        public string doc_dict_format { get; set; } // nullable; 'csv' | 'tsv' | 'xlsx'; required when doc_dict_url is set
        public string[] doc_tm_urls { get; set; } // nullable; SAS, read: encrypted TMX files (slots 'tm0'..), optional, max DocumentJobLimits.MaxTranslationMemories
    }

    public class TranslatorRequestMessage : ITranslatorRequestMessage
    {
        public string request_id { get; set; }
        public string key_id { get; set; } // nullable
        public byte[] encrypted_key { get; set; } // nullable
        public byte[] entropy { get; set; } // nullable
        public byte[] maybe_encrypted_body { get; set; }

        public string GetRequestId()
        {
            return request_id;
        }
    }

    public class TranslatorResponseBody
    {
        public TranslatorResultTypeEnum result_type { get; set; }
        public string error_details { get; set; } // nullable
        public int? allowed_beamwidth { get; set; } // nullable
        public Translation[] translations { get; set; } // nullable
        public DocumentResult document { get; set; } // nullable; summary of a translate_document job
    }

    public class TranslatorResponseMessage : ITranslatorResponseMessage
    {
        public string request_id { get; set; }
        public TranslatorRequestTypeEnum request_type { get; set; }
        public byte[] object_id { get; set; }
        public int consumed_units { get; set; }
        public float time_ms { get; set; }
        public string node { get; set; } // nullable
        public string model { get; set; } // nullable
        public string task { get; set; } // nullable
        public string src_lang { get; set; } // nullable
        public string trg_lang { get; set; } // nullable
        public string unsafe_error { get; set; } // nullable
        public string key_id { get; set; } // nullable
        public byte[] entropy { get; set; } // nullable
        public byte[] maybe_encrypted_body { get; set; }

        public string GetRequestId()
        {
            return request_id;
        }
    }
}
