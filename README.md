# IPTranslator.Client

.NET client for the [IP.Translator](https://www.ipappify.de/en/ip-translator) document
translation job API: batch translation of `.docx` documents, **end-to-end
encrypted** — the document is encrypted on your machine and decrypted only on
the GPU worker that translates it; the web service relays it unopened.

- **Post-quantum E2E encryption**: X-Wing KEM (ML-KEM-768 + X25519),
  AES-256-GCM bodies and blobs, hybrid-signed (Ed25519 + ML-DSA-65) key
  announcements. Details in [docs/encryption.md](docs/encryption.md).
- **Document jobs**: create → upload → submit → poll → fetch, with optional
  dictionaries (csv/tsv/xlsx) and translation memories (tmx). Details in
  [docs/document-jobs.md](docs/document-jobs.md).
- Targets `netstandard2.0`; dependencies: BouncyCastle.Cryptography,
  Newtonsoft.Json, Serilog.

This repository is intentionally small so the code — especially the
cryptography — is practical to review. See [SECURITY.md](SECURITY.md) for
reporting vulnerabilities.

## Install

```
dotnet add package IPTranslator.Client
```

## Quick start

You need an API key and the service's key material: either the pinned X-Wing
public key (`.xwing`) or, recommended, the built-in announcement verification
key (rotation-proof — the current service key is then obtained from the
signed announcement in the Ping response).

```csharp
using IPTranslator.Client;
using IPTranslator.Client.E2E;
using IPTranslator.Client.Messaging;
using IPTranslator.Contracts.Actions;

var requestHandler = new WebApiRequestHandler(
    "https://iptranslator.ipappify.de",
    new ApiKeyMessageHandler(apiKey));

// resolve the service public key from the signed announcement (verified
// against the built-in verification key; the web service cannot forge it)
var ping = await new ManagementClient(requestHandler).Ping(new Ping.Request());
var servicePublicKey = SignedKeyAnnouncement.Parse(ping.SignedServicePublicKey)
    .VerifyAndGetPublicKey(E2EDefaults.ServiceVerificationKey);

var client = new DocumentJobClient(requestHandler, servicePublicKey);

// submit: the document is encrypted locally before upload
var handle = await client.Submit("patent.docx", await File.ReadAllBytesAsync("patent.docx"),
    sourceLanguage: "de", targetLanguage: "en", finalize: true);

// poll: the server holds the call up to 20 s and returns early on changes
GetDocumentJob.Response status;
do { status = await client.GetStatus(handle, waitSeconds: 20); }
while (status.State is DocumentJobStateEnum.queued or DocumentJobStateEnum.running);

// fetch + decrypt the result, end-to-end verified
var result = await client.GetResult(handle);
await File.WriteAllBytesAsync("patent.en.docx", result.Document);
Console.WriteLine($"billed units: {result.ConsumedUnits}");
```

## Example CLI

[`examples/IPTranslator.Client.Cmd`](examples/IPTranslator.Client.Cmd) is a
complete reference implementation:

```
ipt-client-cmd input.docx output.docx service.hybrid --src de --trg en \
    [-f] [-d terms.xlsx] [-m memory.tmx]... [-k <api-key>]
```

The key file is either the pinned X-Wing public key (`*.xwing`) or the
announcement verification key (`*.hybrid`); the API key can also be supplied
via the `IPT_API_KEY` environment variable. Run without arguments for full
usage.

```
dotnet run --project examples/IPTranslator.Client.Cmd -- ...
```

## Building and tests

```
dotnet build IPTranslator.Client.slnx
dotnet test IPTranslator.Client.slnx
```

The tests include cross-language vectors shared with the service (message
AAD formats, `iptd-doc:v1` blobs, announcement signatures), pinned dev keys,
and tamper-detection cases.

## Repository layout

```
src/IPTranslator.Client/        the NuGet package (client, E2E crypto, wire contracts)
examples/IPTranslator.Client.Cmd/  reference CLI
tests/IPTranslator.Client.Tests/   crypto + protocol tests
docs/                           encryption and document-job protocol docs
```

This repository is a curated extract of the IPTranslator codebase: it contains
exactly the client pieces needed for the document job API (plus Ping for key
announcements). The full product (Word add-in, interactive translation, GenAI
review) lives in a private repository which is authoritative; changes here are
synced from it.

## License

[MIT](LICENSE)
