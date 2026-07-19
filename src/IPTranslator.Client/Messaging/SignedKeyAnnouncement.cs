using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Text;

namespace IPTranslator.Client.Messaging
{
    /// <summary>
    /// A signed announcement of the service's X-Wing public key, enabling key
    /// rotation over an untrusted channel (the web app announces it via Ping, but
    /// cannot forge it: the signing keys never leave the service operators).
    ///
    /// The signature is a hybrid of Ed25519 and ML-DSA-65 (FIPS 204) over the same
    /// payload; BOTH must verify. Ed25519 guards against lattice cryptanalysis
    /// surprises, ML-DSA keeps the announcement unforgeable by a quantum attacker.
    ///
    /// Wire format (JSON) and the signing payload must stay byte-identical with
    /// ipt-service's announce.py:
    ///     payload = UTF8("iptr-key:v1:" + public_key + ":" + not_before + ":" + not_after)
    /// </summary>
    public class SignedKeyAnnouncement
    {
        /// <summary>ed25519 pk (32) || ML-DSA-65 pk (1952)</summary>
        public const int VerificationKeySize = 1984;
        private const int Ed25519PublicKeySize = 32;

        public string public_key { get; set; }
        public long not_before { get; set; }
        public long not_after { get; set; }
        public string sig_ed25519 { get; set; }
        public string sig_mldsa65 { get; set; }

        public static SignedKeyAnnouncement Parse(string json)
        {
            var announcement = JsonConvert.DeserializeObject<SignedKeyAnnouncement>(json);
            if (announcement == null || String.IsNullOrEmpty(announcement.public_key) ||
                String.IsNullOrEmpty(announcement.sig_ed25519) || String.IsNullOrEmpty(announcement.sig_mldsa65))
            {
                throw new InvalidOperationException("malformed key announcement");
            }
            return announcement;
        }

        /// <summary>
        /// Verifies the validity window and both signatures; returns the announced
        /// X-Wing public key (base64). Throws <see cref="InvalidOperationException"/>
        /// if anything does not check out.
        /// </summary>
        public string VerifyAndGetPublicKey(string verificationKeyBase64, DateTimeOffset? now = null)
        {
            if (String.IsNullOrEmpty(verificationKeyBase64))
                throw new ArgumentException("verification key must be set", nameof(verificationKeyBase64));
            var verificationKey = Convert.FromBase64String(verificationKeyBase64);
            if (verificationKey.Length != VerificationKeySize)
                throw new InvalidOperationException($"verification key must be {VerificationKeySize} bytes");

            var time = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
            if (time < not_before || time > not_after)
                throw new InvalidOperationException("key announcement is expired or not yet valid");

            var payload = Encoding.UTF8.GetBytes($"iptr-key:v1:{public_key}:{not_before}:{not_after}");

            var ed25519 = new Ed25519Signer();
            ed25519.Init(false, new Ed25519PublicKeyParameters(verificationKey, 0));
            ed25519.BlockUpdate(payload, 0, payload.Length);
            if (!ed25519.VerifySignature(Convert.FromBase64String(sig_ed25519)))
                throw new InvalidOperationException("key announcement signature verification failed (Ed25519)");

            var mldsaKey = new byte[VerificationKeySize - Ed25519PublicKeySize];
            Array.Copy(verificationKey, Ed25519PublicKeySize, mldsaKey, 0, mldsaKey.Length);
            var mldsa = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
            mldsa.Init(false, MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, mldsaKey));
            mldsa.BlockUpdate(payload, 0, payload.Length);
            if (!mldsa.VerifySignature(Convert.FromBase64String(sig_mldsa65)))
                throw new InvalidOperationException("key announcement signature verification failed (ML-DSA-65)");

            return public_key;
        }
    }
}
