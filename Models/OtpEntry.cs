namespace VaultwardenOtpImporter.Models;

public sealed class OtpEntry
{
    public required string Account { get; init; }
    public required string Issuer { get; init; }
    public required string Secret { get; init; }
    public required string Algorithm { get; init; }
    public required int Digits { get; init; }
    public int Period { get; init; } = 30;

    public string DisplayIssuer => string.IsNullOrWhiteSpace(Issuer) ? "(sin emisor)" : Issuer;

    public string ToOtpAuthUri()
    {
        var label = string.IsNullOrWhiteSpace(Issuer) ? Account : $"{Issuer}:{Account}";
        var query = new List<string>
        {
            $"secret={Uri.EscapeDataString(Secret)}"
        };

        if (!string.IsNullOrWhiteSpace(Issuer))
            query.Add($"issuer={Uri.EscapeDataString(Issuer)}");
        if (!string.Equals(Algorithm, "SHA1", StringComparison.Ordinal))
            query.Add($"algorithm={Algorithm}");
        if (Digits != 6)
            query.Add($"digits={Digits}");
        if (Period != 30)
            query.Add($"period={Period}");

        return $"otpauth://totp/{Uri.EscapeDataString(label)}?{string.Join("&", query)}";
    }
}
