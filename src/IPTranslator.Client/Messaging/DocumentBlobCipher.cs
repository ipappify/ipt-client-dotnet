using System;
using System.Text;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace IPTranslator.Client.Messaging
{
    /// <summary>
    /// Document-blob encryption for asynchronous jobs (<c>iptd-doc:v1</c>). A blob
    /// travels through blob storage AES-256-GCM-encrypted under a per-job key; the
    /// client generates the key (<see cref="NewKey"/>) and transports it INSIDE
    /// the encrypted request body (<c>doc_key</c>) — the WebApp relays the request
    /// unopened, so only the client and the worker ever see it (same trust model
    /// as the message bodies; no second KEM).
    ///
    /// Blob layout: <c>12-byte nonce || ciphertext || 16-byte tag</c>. The GCM AAD
    /// binds job identity and blob slot, so a blob cannot be replayed in another
    /// slot or under another job: <c>iptd-doc:v1:{job_id}:{slot}</c>. Slots:
    /// <c>in</c>/<c>out</c> for document-translation jobs, plus <c>dict</c>
    /// (dictionary file) and <c>tm0..tmN</c> (TMX translation memories) for their
    /// optional job inputs; <c>ctx0..ctxN</c> (context files) and <c>out</c>
    /// (result report) for genai jobs.
    ///
    /// Must stay byte-identical with <c>ipt_service/docblob.py</c>; both test
    /// suites pin the same fixed-nonce vectors.
    /// </summary>
    public static class DocumentBlobCipher
    {
        public const string Version = "iptd-doc:v1";
        public const int KeySize = 32;
        public const int NonceSize = 12;
        public const int TagSize = 16;
        private const int TagBits = TagSize * 8;

        public const string DirectionIn = "in";   // client -> worker (input document)
        public const string DirectionOut = "out"; // worker -> client (result document/report)

        public const string DictionarySlot = "dict"; // client -> worker (optional dictionary file)

        /// <summary>Slot of the i-th genai context file (<c>ctx0..ctxN</c>).</summary>
        public static string ContextSlot(int index)
        {
            if (index < 0)
                throw new ArgumentOutOfRangeException(nameof(index));
            return $"ctx{index}";
        }

        /// <summary>Slot of the i-th translation-memory file (<c>tm0..tmN</c>).</summary>
        public static string TranslationMemorySlot(int index)
        {
            if (index < 0)
                throw new ArgumentOutOfRangeException(nameof(index));
            return $"tm{index}";
        }

        /// <summary>Fresh per-job 256-bit blob key (client-side; never persisted server-side).</summary>
        public static byte[] NewKey()
        {
            var key = new byte[KeySize];
            new SecureRandom().NextBytes(key);
            return key;
        }

        private static bool IsValidIndexedSlot(string slot, string prefix)
        {
            // {prefix}0..{prefix}N, no leading zeros
            if (slot == null || slot.Length < prefix.Length + 1 || !slot.StartsWith(prefix))
                return false;
            if (slot.Length > prefix.Length + 1 && slot[prefix.Length] == '0')
                return false;
            for (var i = prefix.Length; i < slot.Length; i++)
                if (slot[i] < '0' || slot[i] > '9')
                    return false;
            return true;
        }

        private static bool IsValidSlot(string slot)
        {
            if (slot == DirectionIn || slot == DirectionOut || slot == DictionarySlot)
                return true;
            return IsValidIndexedSlot(slot, "ctx") || IsValidIndexedSlot(slot, "tm");
        }

        public static byte[] DocumentAad(string jobId, string slot)
        {
            if (!IsValidSlot(slot))
                throw new ArgumentException($"slot must be '{DirectionIn}', '{DirectionOut}', '{DictionarySlot}', 'ctx<i>' or 'tm<i>', got '{slot}'", nameof(slot));
            if (string.IsNullOrEmpty(jobId))
                throw new ArgumentException("jobId is required", nameof(jobId));
            return Encoding.UTF8.GetBytes($"{Version}:{jobId}:{slot}");
        }

        public static byte[] Encrypt(byte[] key, string jobId, string slot, byte[] data)
        {
            var nonce = new byte[NonceSize];
            new SecureRandom().NextBytes(nonce);
            return Encrypt(key, jobId, slot, data, nonce);
        }

        /// <summary>Fixed-nonce overload — the test seam for the cross-language vectors.
        /// Production callers must use the random-nonce overload.</summary>
        public static byte[] Encrypt(byte[] key, string jobId, string slot, byte[] data, byte[] nonce)
        {
            if (key == null || key.Length != KeySize)
                throw new ArgumentException($"key must be {KeySize} bytes", nameof(key));
            if (nonce == null || nonce.Length != NonceSize)
                throw new ArgumentException($"nonce must be {NonceSize} bytes", nameof(nonce));

            var cipher = new GcmBlockCipher(Org.BouncyCastle.Crypto.AesUtilities.CreateEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(key), TagBits, nonce, DocumentAad(jobId, slot)));
            var output = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            cipher.DoFinal(output, len);

            var blob = new byte[NonceSize + output.Length];
            Buffer.BlockCopy(nonce, 0, blob, 0, NonceSize);
            Buffer.BlockCopy(output, 0, blob, NonceSize, output.Length);
            return blob;
        }

        public static byte[] Decrypt(byte[] key, string jobId, string slot, byte[] blob)
        {
            if (key == null || key.Length != KeySize)
                throw new ArgumentException($"key must be {KeySize} bytes", nameof(key));
            if (blob == null || blob.Length < NonceSize + TagSize)
                throw new ArgumentException($"blob too short to be a {Version} document ({blob?.Length ?? 0} bytes)", nameof(blob));

            var nonce = new byte[NonceSize];
            Buffer.BlockCopy(blob, 0, nonce, 0, NonceSize);

            var cipher = new GcmBlockCipher(Org.BouncyCastle.Crypto.AesUtilities.CreateEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), TagBits, nonce, DocumentAad(jobId, slot)));
            var output = new byte[cipher.GetOutputSize(blob.Length - NonceSize)];
            var len = cipher.ProcessBytes(blob, NonceSize, blob.Length - NonceSize, output, 0);
            try
            {
                cipher.DoFinal(output, len);
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                throw new InvalidOperationException(
                    "document authentication failed: wrong key, job_id, direction, or tampered blob", e);
            }
            return output;
        }
    }
}
