using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using VaultwardenOtpImporter.Models;

namespace VaultwardenOtpImporter.Services;

public sealed class BitwardenCliService : IDisposable
{
    private readonly string _appDataDirectory;
    private readonly string _cliPath;
    private string? _session;
    private string? _configuredServer;
    private string? _loggedInEmail;

    public BitwardenCliService()
    {
        var bundledCli = Path.Combine(AppContext.BaseDirectory, "bw.exe");
        _cliPath = File.Exists(bundledCli) ? bundledCli : "bw";
        _appDataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "VaultwardenOtpImporter",
            "BitwardenCli");
        Directory.CreateDirectory(_appDataDirectory);
    }

    public async Task<IReadOnlyList<VaultAccount>> ConnectAndLoadAsync(
        string server,
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Host is not ("localhost" or "127.0.0.1")))
            throw new InvalidOperationException("Indica una URL HTTPS válida para Vaultwarden.");

        var normalizedServer = server.TrimEnd('/');
        var normalizedEmail = email.Trim();
        var canReuseSession = !string.IsNullOrWhiteSpace(_session) &&
                              string.Equals(_configuredServer, normalizedServer, StringComparison.OrdinalIgnoreCase) &&
                              string.Equals(_loggedInEmail, normalizedEmail, StringComparison.OrdinalIgnoreCase);

        if (!canReuseSession)
        {
            if (!string.IsNullOrWhiteSpace(_session))
                await RunAllowFailureAsync(["logout"], null, cancellationToken);

            if (!string.Equals(_configuredServer, normalizedServer, StringComparison.OrdinalIgnoreCase))
            {
                await RunAsync(["config", "server", normalizedServer], null, cancellationToken);
                _configuredServer = normalizedServer;
            }

            var passwordFile = Path.Combine(_appDataDirectory, $"password-{Guid.NewGuid():N}.tmp");
            try
            {
                await File.WriteAllTextAsync(passwordFile, password, new UTF8Encoding(false), cancellationToken);
                _session = (await RunAsync(
                    ["login", normalizedEmail, "--passwordfile", passwordFile, "--raw", "--nointeraction"],
                    null,
                    cancellationToken)).Trim();
                _loggedInEmail = normalizedEmail;
            }
            finally
            {
                try
                {
                    if (File.Exists(passwordFile))
                    {
                        File.WriteAllText(passwordFile, string.Empty);
                        File.Delete(passwordFile);
                    }
                }
                catch
                {
                    // El fichero está dentro del directorio privado y se limpiará al iniciar de nuevo.
                }
            }
        }

        if (string.IsNullOrWhiteSpace(_session))
            throw new InvalidOperationException("Vaultwarden no ha devuelto una sesión válida.");

        // Login ya descarga y guarda la bóveda. Un sync adicional duplicaba el
        // tiempo de espera sin aportar datos más recientes en este flujo.
        var json = await RunSessionAsync(["list", "items"], cancellationToken);
        var array = JsonNode.Parse(json)?.AsArray()
            ?? throw new InvalidOperationException("Vaultwarden devolvió una respuesta vacía.");
        var accounts = array
            .Where(node => node is not null)
            .Select(node =>
            {
                var nonNullNode = node!;
                var account = nonNullNode.Deserialize<VaultAccount>()
                    ?? throw new InvalidOperationException("Vaultwarden devolvió una cuenta no válida.");
                account.RawJson = nonNullNode.ToJsonString();
                return account;
            })
            .ToList();

        return accounts
            .Where(account => account.Login is not null)
            .OrderBy(account => account.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    public async Task TransferTotpAsync(
        VaultAccount account,
        OtpEntry otp,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        EnsureSession();
        progress?.Report("Preparando la cuenta seleccionada…");
        if (string.IsNullOrWhiteSpace(account.RawJson))
            throw new InvalidOperationException("No se conservan los datos completos de la cuenta seleccionada. Pulsa Importar de nuevo.");
        var item = JsonNode.Parse(account.RawJson)?.AsObject()
            ?? throw new InvalidOperationException("Los datos de la cuenta seleccionada no son válidos.");
        var login = item["login"]?.AsObject()
            ?? throw new InvalidOperationException("La cuenta seleccionada no es un acceso válido.");

        login["totp"] = otp.ToOtpAuthUri();
        // `bw encode` solo aplica Base64 al JSON. Hacerlo aquí evita un fallo de
        // interoperabilidad WASM presente en algunas versiones recientes de bw.
        var itemJson = item.ToJsonString();
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(itemJson));
        progress?.Report("Guardando el OTP cifrado en Vaultwarden…");
        await RunSessionAsync(["edit", "item", account.Id, encoded], cancellationToken);
        account.RawJson = itemJson;
    }

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        if (_session is null) return;
        await RunAllowFailureAsync(["logout"], null, cancellationToken);
        _session = null;
        _loggedInEmail = null;
    }

    private void EnsureSession()
    {
        if (string.IsNullOrWhiteSpace(_session))
            throw new InvalidOperationException("No hay una sesión abierta con Vaultwarden.");
    }

    private Task<string> RunSessionAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken) =>
        RunSessionAsync(arguments, cancellationToken, null);

    private Task<string> RunSessionAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken,
        string? standardInput)
    {
        EnsureSession();
        // Bitwarden CLI 2024.4.1 requiere las opciones globales después del
        // comando: `bw list items --session ...`, tal como indica su ayuda.
        var completeArguments = arguments.Concat(["--session", _session!]).ToArray();
        return RunAsync(completeArguments, null, cancellationToken, standardInput);
    }

    private async Task RunAllowFailureAsync(
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? secretEnvironment,
        CancellationToken cancellationToken)
    {
        try { await RunAsync(arguments, secretEnvironment, cancellationToken); }
        catch (BitwardenCliException) { }
    }

    private async Task<string> RunAsync(
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? secretEnvironment,
        CancellationToken cancellationToken,
        string? standardInput = null)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _cliPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        startInfo.Environment["BITWARDENCLI_APPDATA_DIR"] = _appDataDirectory;
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        // Mantener las opciones globales al final es necesario para el ejecutable
        // 2024.4.1 incluido.
        if (!arguments.Contains("--nointeraction", StringComparer.OrdinalIgnoreCase))
            startInfo.ArgumentList.Add("--nointeraction");
        if (secretEnvironment is not null)
            foreach (var pair in secretEnvironment)
                startInfo.Environment[pair.Key] = pair.Value;

        Process process;
        try
        {
            process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("No se ha podido iniciar Bitwarden CLI.");
        }
        catch (System.ComponentModel.Win32Exception exception)
        {
            throw new InvalidOperationException(
                "No se encuentra Bitwarden CLI. Coloca bw.exe junto a la aplicación o instálalo en PATH.",
                exception);
        }

        using (process)
        {
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(TimeSpan.FromSeconds(45));
            var commandToken = timeoutSource.Token;
            try
            {
                if (standardInput is not null)
                {
                    await process.StandardInput.WriteAsync(standardInput.AsMemory(), commandToken);
                    process.StandardInput.Close();
                }

                var stdoutTask = process.StandardOutput.ReadToEndAsync(commandToken);
                var stderrTask = process.StandardError.ReadToEndAsync(commandToken);
                await process.WaitForExitAsync(commandToken);
                var stdout = await stdoutTask;
                var stderr = await stderrTask;
                if (process.ExitCode != 0)
                    throw new BitwardenCliException(SanitizeError($"{stderr}\n{stdout}", arguments));
                return stdout;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                }
                catch { }
                var command = GetCommandName(arguments);
                throw new InvalidOperationException(
                    $"Bitwarden CLI no respondió durante «{command}» y la operación se canceló.");
            }
        }
    }

    private static string SanitizeError(string stderr, IReadOnlyList<string> arguments)
    {
        // Algunos errores internos de bw incluyen el objeto completo de la bóveda
        // (incluidos campos cifrados o secretos). Nunca se devuelve stderr en bruto.
        var command = GetCommandName(arguments);
        if (stderr.Contains("invalid type", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("JsValue", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("wasm", StringComparison.OrdinalIgnoreCase))
            return $"Bitwarden CLI ha producido un error interno durante «{command}». Actualiza bw e inténtalo de nuevo.";

        if (stderr.Contains("not found", StringComparison.OrdinalIgnoreCase))
            return "No se ha encontrado la cuenta solicitada en Vaultwarden.";
        if (stderr.Contains("two-step", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("2fa", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("verification code", StringComparison.OrdinalIgnoreCase))
            return "La cuenta requiere verificación en dos pasos. Este inicio de sesión necesita un código 2FA.";
        if (stderr.Contains("bot", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("captcha", StringComparison.OrdinalIgnoreCase))
            return "Vaultwarden ha solicitado una comprobación adicional de acceso. Inicia sesión una vez desde Bitwarden CLI o utiliza una clave API personal.";
        if (stderr.Contains("getaddrinfo", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("connect", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("certificate", StringComparison.OrdinalIgnoreCase))
            return "No se ha podido conectar con el servidor de Vaultwarden. Comprueba la URL y el certificado HTTPS.";
        if (stderr.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("invalid master password", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("username or password", StringComparison.OrdinalIgnoreCase))
            return "Vaultwarden ha rechazado las credenciales o la sesión.";

        return $"Bitwarden CLI no ha podido completar «{command}».";
    }

    private static string GetCommandName(IReadOnlyList<string> arguments)
    {
        string[] commands =
        [
            "config", "login", "logout", "lock", "unlock", "sync",
            "status", "list", "get", "create", "edit", "delete"
        ];
        return arguments.FirstOrDefault(argument =>
            commands.Contains(argument, StringComparer.OrdinalIgnoreCase)) ?? "operación";
    }

    public void Dispose()
    {
        _session = null;
        GC.SuppressFinalize(this);
    }

    private sealed class BitwardenCliException(string message) : Exception(message);
}
