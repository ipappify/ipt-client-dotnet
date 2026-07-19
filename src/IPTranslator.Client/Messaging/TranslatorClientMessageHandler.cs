using IPTranslator.Contracts.Messaging;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IPTranslator.Client.Messaging
{
    /// <summary>
    /// Builds and parses IPTv3 messages. Bodies are encrypted with AES-256-GCM under a
    /// key transported via the X-Wing KEM; the GCM associated data binds the unencrypted
    /// envelope fields (request_id, key_id, and on responses request_type/consumed_units/
    /// object_id) so they cannot be tampered with independently of the body.
    /// </summary>
    public class TranslatorClientMessageHandler
    {
        public class TupleConverter : JsonConverter
        {
            public override bool CanConvert(Type objectType)
            {
                return
                    objectType == typeof(ValueTuple<int, int>) ||
                    objectType == typeof(ValueTuple<int, int, int>);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                var list = serializer.Deserialize<List<int>>(reader);
                // TODO handle (int,int,int)
                if (objectType == typeof(ValueTuple<int, int>))
                    return (list[0], list[1]);
                else if (objectType == typeof(ValueTuple<int, int, int>))
                    return (list[0], list[1], list[2]);
                else
                    throw new InvalidOperationException("unsupported tuple type");
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                if (value is ValueTuple<int, int> t2)
                    serializer.Serialize(writer, new List<int> { t2.Item1, t2.Item2 });
                else if (value is ValueTuple<int, int, int> t3)
                    serializer.Serialize(writer, new List<int> { t3.Item1, t3.Item2, t3.Item3 });
                else
                    throw new InvalidOperationException("unsupported tuple type");
            }
        }

        private static JsonSerializerSettings serializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            DefaultValueHandling = DefaultValueHandling.Include,
            Formatting = Formatting.None,
            Converters = new List<JsonConverter>
            {
                new Newtonsoft.Json.Converters.StringEnumConverter(),
                new TupleConverter(),
            }
        };

        private readonly string publicKeyBase64;
        private byte[] key;
        private string keyId;
        private byte[] encryptedKey;

        public bool IsEncrypted => publicKeyBase64 != null;

        /// <param name="publicKeyBase64">base64 of the service's 1216-byte X-Wing public key,
        /// or null for unencrypted messaging.</param>
        public TranslatorClientMessageHandler(string publicKeyBase64)
        {
            this.publicKeyBase64 = string.IsNullOrEmpty(publicKeyBase64) ? null : publicKeyBase64;
            key = null;
            keyId = null;
            encryptedKey = null;
            if (this.publicKeyBase64 != null)
            {
                CreateKey();
            }
        }

        private void CreateKey()
        {
            if (publicKeyBase64 == null)
            {
                throw new ArgumentNullException("publicKey must be set");
            }

            keyId = Guid.NewGuid().ToString("N");
            // X-Wing KEM: derives a fresh AES key + the ciphertext that transports it
            (key, encryptedKey) = XWingKem.EncryptKey(Convert.FromBase64String(publicKeyBase64));
        }

        public const int GcmNonceSize = 12; // AES-GCM nonce in ``entropy``
        private const int GcmTagBits = 128;

        /// <summary>
        /// AES-256-GCM: returns (12-byte nonce, ciphertext||16-byte tag). ``aad`` is
        /// authenticated but not encrypted (binds unencrypted envelope fields to the body).
        /// </summary>
        public static (byte[] nonce, byte[] cipher) EncryptGcm(byte[] key, byte[] data, byte[] aad)
        {
            var nonce = new byte[GcmNonceSize];
            new SecureRandom().NextBytes(nonce);
            var cipher = new GcmBlockCipher(Org.BouncyCastle.Crypto.AesUtilities.CreateEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(key), GcmTagBits, nonce, aad));
            var output = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            cipher.DoFinal(output, len);
            return (nonce, output);
        }

        public static byte[] DecryptGcm(byte[] key, byte[] nonce, byte[] data, byte[] aad)
        {
            var cipher = new GcmBlockCipher(Org.BouncyCastle.Crypto.AesUtilities.CreateEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), GcmTagBits, nonce, aad));
            var output = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            try
            {
                cipher.DoFinal(output, len);
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                throw new InvalidOperationException("message authentication failed: body or envelope metadata was tampered with", e);
            }
            return output;
        }

        // AAD formats shared with ipt-service (message.py request_aad/response_aad)
        public static byte[] RequestAad(string requestId, string keyId)
        {
            return Encoding.UTF8.GetBytes($"iptv3-req:v1:{requestId}:{keyId}");
        }

        public static byte[] ResponseAad(TranslatorResponseMessage message)
        {
            var objectId = message.object_id != null && message.object_id.Length > 0 ?
                Convert.ToBase64String(message.object_id) : "";
            var consumedUnits = message.consumed_units.ToString(CultureInfo.InvariantCulture);
            return Encoding.UTF8.GetBytes(
                $"iptv3-rsp:v1:{message.request_id}:{message.key_id}:{message.request_type}:{consumedUnits}:{objectId}");
        }

        public TranslatorRequestMessage BuildRequest(TranslatorRequestBody body, string requestId = null)
        {
            requestId = requestId ?? Guid.NewGuid().ToString("N");
            var encodedBody = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(body, serializerSettings));
            if (!IsEncrypted)
            {
                return new TranslatorRequestMessage
                {
                    request_id = requestId,
                    maybe_encrypted_body = encodedBody
                };
            }
            else
            {
                var (entropy, encryptedBody) = EncryptGcm(key, encodedBody, RequestAad(requestId, keyId));
                return new TranslatorRequestMessage
                {
                    request_id = requestId,
                    key_id = keyId,
                    encrypted_key = encryptedKey,
                    entropy = entropy,
                    maybe_encrypted_body = encryptedBody
                };
            }
        }

        public (TranslatorResponseBody body, string requestId) ParseResponse(TranslatorResponseMessage message)
        {
            if (message.unsafe_error != null)
            {
                throw new InvalidOperationException("service failed with: " + message.unsafe_error);
            }
            if (key == null && message.key_id != null)
            {
                throw new InvalidOperationException("key must be set to decrypt messages");
            }
            if (message.maybe_encrypted_body.Length == 0)
            {
                throw new InvalidOperationException("maybe_encrypted_body must not be empty");
            }
            if (message.key_id == null)
            {
                var body = JsonConvert.DeserializeObject<TranslatorResponseBody>(
                    Encoding.UTF8.GetString(message.maybe_encrypted_body),
                    serializerSettings);
                return (body, message.request_id);
            }
            else
            {
                if (message.key_id != keyId)
                {
                    throw new InvalidOperationException("key_id does not match");
                }
                if (message.entropy.Length != GcmNonceSize)
                {
                    // pre-GCM (AES-CBC) services are long gone; their responses were
                    // unauthenticated, so do not fall back to decrypting them
                    throw new InvalidOperationException("entropy is not an AES-GCM nonce");
                }
                var data = DecryptGcm(key, message.entropy, message.maybe_encrypted_body, ResponseAad(message));
                var body = JsonConvert.DeserializeObject<TranslatorResponseBody>(
                    Encoding.UTF8.GetString(data),
                    serializerSettings);
                return (body, message.request_id);
            }
        }
    }
}
