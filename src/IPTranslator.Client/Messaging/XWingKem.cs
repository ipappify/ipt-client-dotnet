using System;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace IPTranslator.Client.Messaging
{
    /// <summary>
    /// X-Wing hybrid post-quantum KEM (draft-connolly-cfrg-xwing-kem):
    /// ML-KEM-768 + X25519 combined with SHA3-256, built on BouncyCastle.
    ///
    /// Client side only (encapsulation): being a KEM, X-Wing does not encrypt a
    /// caller-chosen key — <see cref="EncryptKey"/> derives a fresh 32-byte AES key
    /// and returns it together with the ciphertext ("encrypted key") from which the
    /// service's private key recovers it.
    /// </summary>
    public static class XWingKem
    {
        /// <summary>ML-KEM-768 encapsulation key (1184) || X25519 public key (32).</summary>
        public const int PublicKeySize = 1216;
        /// <summary>ML-KEM-768 ciphertext (1088) || X25519 ephemeral public key (32).</summary>
        public const int CiphertextSize = 1120;
        /// <summary>Size of the derived AES key.</summary>
        public const int KeySize = 32;

        private const int MLKemPublicKeySize = 1184;
        private const int X25519KeySize = 32;

        // the 6-byte ASCII label "\.//^\" (hex 5c2e2f2f5e5c)
        private static readonly byte[] XWingLabel = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };

        // shared CSPRNG for both component algorithms (BouncyCastle's
        // DigestRandomGenerator is internally synchronized)
        private static readonly SecureRandom Random = new SecureRandom();

        /// <summary>
        /// Derives a fresh 32-byte AES key for the holder of <paramref name="publicKey"/>.
        /// Returns the key (to use locally) and the 1120-byte encrypted key (to transmit).
        /// </summary>
        public static (byte[] key, byte[] encryptedKey) EncryptKey(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != PublicKeySize)
            {
                throw new ArgumentException($"X-Wing public key must be {PublicKeySize} bytes");
            }

            var pkM = new byte[MLKemPublicKeySize];
            var pkX = new byte[X25519KeySize];
            Array.Copy(publicKey, 0, pkM, 0, MLKemPublicKeySize);
            Array.Copy(publicKey, MLKemPublicKeySize, pkX, 0, X25519KeySize);

            // ML-KEM-768 encapsulation; the explicit SecureRandom pins the entropy
            // source rather than relying on BouncyCastle's registrar default
            var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
            encapsulator.Init(new ParametersWithRandom(
                MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, pkM), Random));
            var ctM = new byte[encapsulator.EncapsulationLength];
            var ssM = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(ctM, 0, ctM.Length, ssM, 0, ssM.Length);

            // X25519 with an ephemeral key; the ephemeral public key is the ciphertext part
            var ephemeral = new X25519PrivateKeyParameters(Random);
            var ctX = ephemeral.GeneratePublicKey().GetEncoded();
            var agreement = new X25519Agreement();
            agreement.Init(ephemeral);
            var ssX = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(pkX), ssX, 0);

            // combiner: SHA3-256(ssM || ssX || ctX || pkX || XWingLabel)
            var digest = new Sha3Digest(256);
            digest.BlockUpdate(ssM, 0, ssM.Length);
            digest.BlockUpdate(ssX, 0, ssX.Length);
            digest.BlockUpdate(ctX, 0, ctX.Length);
            digest.BlockUpdate(pkX, 0, pkX.Length);
            digest.BlockUpdate(XWingLabel, 0, XWingLabel.Length);
            var key = new byte[KeySize];
            digest.DoFinal(key, 0);

            // wipe the intermediate shared secrets: only the derived key may
            // outlive this call (best effort — the ephemeral private key inside
            // the BouncyCastle objects offers no wipe API, and the GC may have
            // moved copies)
            Array.Clear(ssM, 0, ssM.Length);
            Array.Clear(ssX, 0, ssX.Length);

            var encryptedKey = new byte[CiphertextSize];
            Array.Copy(ctM, 0, encryptedKey, 0, ctM.Length);
            Array.Copy(ctX, 0, encryptedKey, ctM.Length, ctX.Length);
            return (key, encryptedKey);
        }
    }
}
