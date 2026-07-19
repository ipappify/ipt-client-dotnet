using IPTranslator.Client.Messaging;
using IPTranslator.Contracts;
using IPTranslator.Contracts.Actions;
using IPTranslator.Contracts.Messaging;
using System.Text;

namespace IPTranslator.Client.Cmd;

/// <summary>
/// ipt-client-cmd — submits a .docx document translation job via the
/// end-to-end encrypted <see cref="DocumentJobClient"/>, waits for
/// completion, and writes the translated document to the output path.
/// Exit codes: 0 success, 1 unexpected error, 2 usage error,
/// 3 job did not complete (failed or canceled).
/// </summary>
internal static class Program
{
    private const string ApiKeyEnvVar = "IPT_API_KEY";

    private static readonly string Usage = $"""
        usage:
          ipt-client-cmd <input.docx> <output.docx> <key-file> --src <lang> --trg <lang>
                         [-f|--finalize] [-d|--dictionary <file>] [-m|--tm <file.tmx>]...
                         [-s|--service-url <url>] [-k|--api-key <key>]

        key-file (raw binary or base64 text, chosen by extension):
          *.xwing   the service's X-Wing public key ({XWingKem.PublicKeySize} bytes)
          *.hybrid  the Ed25519+ML-DSA-65 verification key ({SignedKeyAnnouncement.VerificationKeySize} bytes);
                    the service key is then obtained from the Ping response's
                    signed announcement, verified against this key

        --src/--trg  source/target language (2-letter iso), required
        -f           ask the worker to finalize the document
        -d           dictionary (.csv, .tsv or .xlsx), applied per segment
        -m           translation memory (.tmx); repeat for multiple (max {DocumentJobLimits.MaxTranslationMemories})
        -s           service base url (default: {Constants.ServiceUrl})
        -k           api key; falls back to the {ApiKeyEnvVar} environment variable
        """;

    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = Options.Parse(args);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            return await Run(options, cts.Token);
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine();
            Console.Error.WriteLine(Usage);
            return 2;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("canceled.");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> Run(Options options, CancellationToken cancel)
    {
        var requestHandler = new WebApiRequestHandler(options.ServiceUrl,
            options.ApiKey is null ? null : new ApiKeyMessageHandler(options.ApiKey));

        var servicePublicKey = await ResolveServicePublicKey(options.KeyFile, requestHandler, cancel);
        var client = new DocumentJobClient(requestHandler, servicePublicKey);

        var documentBytes = await File.ReadAllBytesAsync(options.InputFile, cancel);
        var documentName = Path.GetFileName(options.InputFile);

        var dictionary = options.DictionaryFile is null
            ? null
            : await File.ReadAllBytesAsync(options.DictionaryFile, cancel);
        var dictionaryFormat = options.DictionaryFile is null
            ? null
            : Path.GetExtension(options.DictionaryFile).TrimStart('.').ToLowerInvariant();
        var translationMemories = new List<byte[]>();
        foreach (var tmFile in options.TranslationMemoryFiles)
            translationMemories.Add(await File.ReadAllBytesAsync(tmFile, cancel));

        Console.WriteLine($"submitting {documentName} ({documentBytes.Length:N0} bytes), " +
            $"{options.SourceLanguage} -> {options.TargetLanguage}, finalize: {options.Finalize}" +
            (dictionary is null ? "" : $", dictionary: {Path.GetFileName(options.DictionaryFile)}") +
            (translationMemories.Count == 0 ? "" : $", translation memories: {translationMemories.Count}") +
            " ...");

        var handle = await client.Submit(documentName, documentBytes,
            options.SourceLanguage, options.TargetLanguage, options.Finalize,
            dictionary: dictionary, dictionaryFormat: dictionaryFormat,
            translationMemories: translationMemories.Count > 0 ? translationMemories : null,
            cancel: cancel);
        Console.WriteLine($"job {handle.JobId:N} submitted.");

        var status = await PollUntilTerminal(client, handle, cancel);
        if (status.State != DocumentJobStateEnum.done)
        {
            Console.Error.WriteLine($"job ended {status.State}" +
                (string.IsNullOrEmpty(status.ErrorCode) ? "." : $" ({status.ErrorCode})."));
            return 3;
        }

        var result = await client.GetResult(handle, cancel);
        await File.WriteAllBytesAsync(options.OutputFile, result.Document, cancel);
        Console.WriteLine($"result written to {options.OutputFile} ({result.Document.Length:N0} bytes).");
        if (result.Summary is { } summary)
            Console.WriteLine($"summary: {summary.translated}/{summary.total} translated, {summary.failed} failed.");
        Console.WriteLine($"consumed units: {result.ConsumedUnits}.");
        return 0;
    }

    private static async Task<GetDocumentJob.Response> PollUntilTerminal(
        DocumentJobClient client, DocumentJobClient.DocumentJobHandle handle, CancellationToken cancel)
    {
        var lastState = (DocumentJobStateEnum?)null;
        var lastDone = -1;
        while (true)
        {
            // the server holds the call up to 20 s and returns early on any
            // state/progress change, so this loop is not a tight poll
            GetDocumentJob.Response status;
            try
            {
                status = await client.GetStatus(handle, waitSeconds: 20, cancel);
            }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested)
            {
                Console.Error.WriteLine("canceling job ...");
                await client.Cancel(handle);
                throw;
            }
            if (status.State != lastState || status.ProgressDone != lastDone)
            {
                Console.WriteLine($"state: {status.State}, progress: {status.ProgressDone}/{status.ProgressTotal}");
                lastState = status.State;
                lastDone = status.ProgressDone;
            }
            if (status.State != DocumentJobStateEnum.queued && status.State != DocumentJobStateEnum.running)
                return status;
        }
    }

    /// <summary>
    /// Resolves the service's X-Wing public key from the key file: an .xwing
    /// file holds it directly; a .hybrid file holds the verification key for
    /// the signed announcement delivered in the Ping response.
    /// </summary>
    private static async Task<string> ResolveServicePublicKey(string keyFile,
        IRequestHandler requestHandler, CancellationToken cancel)
    {
        var bytes = await File.ReadAllBytesAsync(keyFile, cancel);
        switch (Path.GetExtension(keyFile).ToLowerInvariant())
        {
            case ".xwing":
                return DecodeKey(bytes, XWingKem.PublicKeySize, keyFile);

            case ".hybrid":
                var verificationKey = DecodeKey(bytes, SignedKeyAnnouncement.VerificationKeySize, keyFile);
                var ping = await new ManagementClient(requestHandler).Ping(new Ping.Request(), cancel);
                if (string.IsNullOrEmpty(ping.SignedServicePublicKey))
                    throw new InvalidOperationException("the service did not announce a signed public key (Ping).");
                var publicKey = SignedKeyAnnouncement.Parse(ping.SignedServicePublicKey)
                    .VerifyAndGetPublicKey(verificationKey);
                Console.WriteLine("service public key obtained from verified signed announcement.");
                return publicKey;

            default:
                throw new UsageException($"unsupported key file extension '{Path.GetExtension(keyFile)}' (expected .xwing or .hybrid).");
        }
    }

    /// <summary>Accepts the raw key (exact size) or a base64 text file; returns the base64.</summary>
    private static string DecodeKey(byte[] fileBytes, int keySize, string keyFile)
    {
        if (fileBytes.Length == keySize)
            return Convert.ToBase64String(fileBytes);

        var offset = fileBytes is [0xEF, 0xBB, 0xBF, ..] ? 3 : 0; // skip a UTF-8 BOM
        var text = Encoding.ASCII.GetString(fileBytes, offset, fileBytes.Length - offset).Trim();
        try
        {
            if (Convert.FromBase64String(text).Length == keySize)
                return text;
        }
        catch (FormatException)
        {
        }
        throw new InvalidOperationException(
            $"'{keyFile}' is neither a raw {keySize}-byte key nor its base64 encoding.");
    }

    private sealed class UsageException(string message) : Exception(message);

    private sealed class Options
    {
        public required string InputFile { get; init; }
        public required string OutputFile { get; init; }
        public required string KeyFile { get; init; }
        public required string SourceLanguage { get; init; }
        public required string TargetLanguage { get; init; }
        public bool Finalize { get; init; }
        public string? DictionaryFile { get; init; }
        public required IReadOnlyList<string> TranslationMemoryFiles { get; init; }
        public required string ServiceUrl { get; init; }
        public string? ApiKey { get; init; }

        public static Options Parse(string[] args)
        {
            var positional = new List<string>();
            var named = new Dictionary<string, string>(StringComparer.Ordinal);
            var translationMemoryFiles = new List<string>();
            var finalize = false;

            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-f" or "--finalize":
                        finalize = true;
                        break;
                    case "-m" or "--tm" or "--translation-memory":
                        if (i + 1 >= args.Length)
                            throw new UsageException($"option '{args[i]}' requires a value.");
                        translationMemoryFiles.Add(args[++i]);
                        break;
                    case "--src" or "--trg" or "-s" or "--service-url" or "-k" or "--api-key" or "-d" or "--dictionary":
                        if (i + 1 >= args.Length)
                            throw new UsageException($"option '{args[i]}' requires a value.");
                        named[args[i].TrimStart('-') switch
                        {
                            "s" => "service-url",
                            "k" => "api-key",
                            "d" => "dictionary",
                            var name => name,
                        }] = args[++i];
                        break;
                    case var arg when arg.StartsWith('-'):
                        throw new UsageException($"unknown option '{arg}'.");
                    case var arg:
                        positional.Add(arg);
                        break;
                }
            }

            if (positional.Count != 3)
                throw new UsageException($"expected 3 arguments (input, output, key file), got {positional.Count}.");
            if (!File.Exists(positional[0]))
                throw new UsageException($"input file '{positional[0]}' does not exist.");
            if (!File.Exists(positional[2]))
                throw new UsageException($"key file '{positional[2]}' does not exist.");
            if (!named.ContainsKey("src") || !named.ContainsKey("trg"))
                throw new UsageException("--src and --trg are required.");

            var dictionaryFile = named.GetValueOrDefault("dictionary");
            if (dictionaryFile != null)
            {
                if (!File.Exists(dictionaryFile))
                    throw new UsageException($"dictionary file '{dictionaryFile}' does not exist.");
                var format = Path.GetExtension(dictionaryFile).TrimStart('.').ToLowerInvariant();
                if (Array.IndexOf(DocumentJobLimits.DictionaryFormats, format) < 0)
                    throw new UsageException(
                        $"dictionary file '{dictionaryFile}' must be .{string.Join(", .", DocumentJobLimits.DictionaryFormats)}.");
            }
            if (translationMemoryFiles.Count > DocumentJobLimits.MaxTranslationMemories)
                throw new UsageException(
                    $"at most {DocumentJobLimits.MaxTranslationMemories} translation memories are supported.");
            foreach (var tmFile in translationMemoryFiles)
            {
                if (!File.Exists(tmFile))
                    throw new UsageException($"translation memory '{tmFile}' does not exist.");
                if (!string.Equals(Path.GetExtension(tmFile), ".tmx", StringComparison.OrdinalIgnoreCase))
                    throw new UsageException($"translation memory '{tmFile}' must be a .tmx file.");
            }

            var apiKey = named.GetValueOrDefault("api-key")
                ?? Environment.GetEnvironmentVariable(ApiKeyEnvVar);
            return new Options
            {
                InputFile = positional[0],
                OutputFile = positional[1],
                KeyFile = positional[2],
                SourceLanguage = named["src"],
                TargetLanguage = named["trg"],
                Finalize = finalize,
                DictionaryFile = dictionaryFile,
                TranslationMemoryFiles = translationMemoryFiles,
                ServiceUrl = named.GetValueOrDefault("service-url") ?? Constants.ServiceUrl,
                ApiKey = string.IsNullOrEmpty(apiKey) ? null : apiKey,
            };
        }
    }
}
