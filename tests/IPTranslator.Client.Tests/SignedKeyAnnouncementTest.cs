using Xunit;
using IPTranslator.Client.Messaging;

namespace IPTranslator.Client.Tests
{
    public class SignedKeyAnnouncementTest
    {
        // the fixture was signed by ipt-service's announce.py: parsing + verifying it
        // here is the cross-language compatibility test
        private static SignedKeyAnnouncement ParseFixture() =>
            SignedKeyAnnouncement.Parse(DevKeys.AnnouncementJson);

        [Fact]
        public void TestVerifiesPythonSignedAnnouncement()
        {
            var announcement = ParseFixture();
            var publicKey = announcement.VerifyAndGetPublicKey(DevKeys.VerificationKeyBase64);
            Assert.Equal(DevKeys.PublicKeyBase64, publicKey);
        }

        [Fact]
        public void TestRejectsTamperedPublicKey()
        {
            var announcement = ParseFixture();
            // swap in a different (well-formed) X-Wing key without re-signing
            var tampered = Convert.FromBase64String(announcement.public_key);
            tampered[0] ^= 0x01;
            announcement.public_key = Convert.ToBase64String(tampered);

            var ex = Assert.Throws<InvalidOperationException>(() =>
                announcement.VerifyAndGetPublicKey(DevKeys.VerificationKeyBase64));
            Assert.Contains("signature", ex.Message);
        }

        [Fact]
        public void TestRejectsExtendedValidity()
        {
            var announcement = ParseFixture();
            announcement.not_after += 3600; // extend without re-signing

            var ex = Assert.Throws<InvalidOperationException>(() =>
                announcement.VerifyAndGetPublicKey(DevKeys.VerificationKeyBase64));
            Assert.Contains("signature", ex.Message);
        }

        [Fact]
        public void TestRejectsOutsideValidityWindow()
        {
            var announcement = ParseFixture();

            var ex = Assert.Throws<InvalidOperationException>(() => announcement.VerifyAndGetPublicKey(
                DevKeys.VerificationKeyBase64, DateTimeOffset.FromUnixTimeSeconds(announcement.not_after + 1)));
            Assert.Contains("expired", ex.Message);

            ex = Assert.Throws<InvalidOperationException>(() => announcement.VerifyAndGetPublicKey(
                DevKeys.VerificationKeyBase64, DateTimeOffset.FromUnixTimeSeconds(announcement.not_before - 1)));
            Assert.Contains("expired", ex.Message);
        }

        [Fact]
        public void TestRejectsWrongVerificationKey()
        {
            var announcement = ParseFixture();
            var wrongKey = new byte[SignedKeyAnnouncement.VerificationKeySize];
            Convert.FromBase64String(DevKeys.VerificationKeyBase64).CopyTo(wrongKey, 0);
            wrongKey[0] ^= 0x01; // corrupt the Ed25519 half

            Assert.Throws<InvalidOperationException>(() =>
                announcement.VerifyAndGetPublicKey(Convert.ToBase64String(wrongKey)));
        }

        [Fact]
        public void TestRejectsSingleValidSignature()
        {
            // hybrid means BOTH must verify: corrupt only the ML-DSA signature so the
            // Ed25519 one alone must not be enough
            var announcement = ParseFixture();
            var sig = Convert.FromBase64String(announcement.sig_mldsa65);
            sig[0] ^= 0x01;
            announcement.sig_mldsa65 = Convert.ToBase64String(sig);

            var ex = Assert.Throws<InvalidOperationException>(() =>
                announcement.VerifyAndGetPublicKey(DevKeys.VerificationKeyBase64));
            Assert.Contains("ML-DSA", ex.Message);
        }

        [Fact]
        public void TestRejectsMalformedJson()
        {
            Assert.ThrowsAny<Exception>(() => SignedKeyAnnouncement.Parse("{}"));
            Assert.ThrowsAny<Exception>(() => SignedKeyAnnouncement.Parse("not json"));
        }
    }
}
