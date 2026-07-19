using System;
using System.Reflection;

namespace IPTranslator.Contracts.Actions
{
    /// <summary>
    /// Ping a service: connectivity check, license/quota state, and the
    /// announcement channel for the service's end-to-end encryption key.
    /// The full service response has more fields (model lists, client
    /// policies); this public client ignores them.
    /// </summary>
    public static class Ping
    {
        public class Request : BaseRequest
        {
            public string Client { get; set; }
            public string ClientVersion { get; set; }

            public Request()
            {
            }

            public Request(Assembly assembly)
            {
                try
                {
                    var name = assembly.GetName();
                    Client = name.Name;
                    ClientVersion = name.Version.ToString();
                }
                catch (Exception)
                {
                }
            }
        }

        public class Response : BaseResponse
        {
            public Guid InstanceId { get; set; }

            public bool HasLicense { get; set; }
            public string LicenseeName { get; set; }
            public bool IsQuotaExceeded { get; set; }
            public string SubscribeUri { get; set; }
            public string UpgradeUri { get; set; }

            /// <summary>
            /// Base64 of the translation service's 1216-byte X-Wing public key, used for
            /// end-to-end encrypted requests. Null if the service does not
            /// offer end-to-end encryption. Clients that pin a key MUST prefer the
            /// pinned key over this value.
            /// </summary>
            public string ServicePublicKey { get; set; }

            /// <summary>
            /// JSON of the hybrid-signed (Ed25519 + ML-DSA-65) announcement of the
            /// service's X-Wing public key. Clients holding the verification key can
            /// accept rotated keys from this untrusted channel; see
            /// IPTranslator.Client.Messaging.SignedKeyAnnouncement.
            /// </summary>
            public string SignedServicePublicKey { get; set; }
        }
    }
}
