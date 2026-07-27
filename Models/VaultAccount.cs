using System.Text.Json.Serialization;

namespace VaultwardenOtpImporter.Models;

public sealed class VaultAccount
{
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("login")]
    public VaultLogin? Login { get; init; }

    [JsonIgnore]
    public string Username => Login?.Username ?? string.Empty;

    [JsonIgnore]
    public string OtpStatus => string.IsNullOrWhiteSpace(Login?.Totp) ? "No" : "Sí";

    [JsonIgnore]
    public string RawJson { get; set; } = string.Empty;
}

public sealed class VaultLogin
{
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("totp")]
    public string? Totp { get; init; }
}
