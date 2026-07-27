using System.Buffers.Binary;
using System.Text;
using VaultwardenOtpImporter.Models;
using ZXing;
using ZXing.Common;
using ZXing.Windows.Compatibility;

namespace VaultwardenOtpImporter.Services;

public sealed class GoogleAuthenticatorDecoder
{
    public IReadOnlyList<OtpEntry> DecodeImage(string imagePath)
    {
        using var bitmap = new Bitmap(imagePath);
        var reader = new BarcodeReader
        {
            AutoRotate = true,
            Options = new DecodingOptions
            {
                TryHarder = true,
                PossibleFormats = [BarcodeFormat.QR_CODE]
            }
        };

        var result = reader.Decode(bitmap)
            ?? throw new InvalidOperationException("No se ha encontrado ningún código QR válido en la imagen.");

        return DecodeMigrationUri(result.Text);
    }

    public IReadOnlyList<OtpEntry> DecodeMigrationUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, "otpauth-migration", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("El QR no es una exportación de Google Authenticator.");

        var encodedData = ParseQuery(uri.Query).GetValueOrDefault("data")
            ?? throw new InvalidOperationException("El QR no contiene los datos de migración.");

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(encodedData.Replace(' ', '+'));
        }
        catch (System.FormatException exception)
        {
            throw new InvalidOperationException("Los datos del QR están dañados.", exception);
        }

        var entries = ParsePayload(payload);
        if (entries.Count == 0)
            throw new InvalidOperationException("El QR no contiene cuentas OTP.");

        return entries;
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        return query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .ToDictionary(
                part => Uri.UnescapeDataString(part[0]),
                part => part.Length > 1 ? Uri.UnescapeDataString(part[1]) : string.Empty,
                StringComparer.OrdinalIgnoreCase);
    }

    private static List<OtpEntry> ParsePayload(ReadOnlySpan<byte> payload)
    {
        var entries = new List<OtpEntry>();
        var position = 0;
        while (position < payload.Length)
        {
            var (field, wireType) = ReadTag(payload, ref position);
            if (field == 1 && wireType == 2)
                entries.Add(ParseOtpParameters(ReadBytes(payload, ref position)));
            else
                SkipField(payload, ref position, wireType);
        }
        return entries;
    }

    private static OtpEntry ParseOtpParameters(ReadOnlySpan<byte> payload)
    {
        byte[]? secret = null;
        var account = string.Empty;
        var issuer = string.Empty;
        var algorithm = 1;
        var digits = 1;
        var type = 0;
        var position = 0;

        while (position < payload.Length)
        {
            var (field, wireType) = ReadTag(payload, ref position);
            if (field == 1 && wireType == 2) secret = ReadBytes(payload, ref position).ToArray();
            else if (field == 2 && wireType == 2) account = Encoding.UTF8.GetString(ReadBytes(payload, ref position));
            else if (field == 3 && wireType == 2) issuer = Encoding.UTF8.GetString(ReadBytes(payload, ref position));
            else if (field == 4 && wireType == 0) algorithm = checked((int)ReadVarint(payload, ref position));
            else if (field == 5 && wireType == 0) digits = checked((int)ReadVarint(payload, ref position));
            else if (field == 6 && wireType == 0) type = checked((int)ReadVarint(payload, ref position));
            else SkipField(payload, ref position, wireType);
        }

        if (secret is null || secret.Length == 0)
            throw new InvalidOperationException("Una entrada OTP no contiene secreto.");
        if (type != 2)
            throw new InvalidOperationException("El QR contiene una entrada HOTP. Esta herramienta solo transfiere TOTP.");

        return new OtpEntry
        {
            Account = account,
            Issuer = issuer,
            Secret = ToBase32(secret),
            Algorithm = algorithm switch
            {
                1 => "SHA1",
                2 => "SHA256",
                3 => "SHA512",
                _ => throw new InvalidOperationException("El QR usa un algoritmo OTP no compatible.")
            },
            Digits = digits switch
            {
                1 => 6,
                2 => 8,
                _ => throw new InvalidOperationException("El QR usa un número de dígitos OTP no compatible.")
            }
        };
    }

    private static (int Field, int WireType) ReadTag(ReadOnlySpan<byte> data, ref int position)
    {
        var tag = checked((int)ReadVarint(data, ref position));
        var field = tag >> 3;
        if (field == 0) throw new InvalidOperationException("Datos protobuf inválidos.");
        return (field, tag & 7);
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> data, ref int position)
    {
        ulong value = 0;
        var shift = 0;
        while (position < data.Length && shift <= 63)
        {
            var current = data[position++];
            value |= (ulong)(current & 0x7f) << shift;
            if ((current & 0x80) == 0) return value;
            shift += 7;
        }
        throw new InvalidOperationException("Datos protobuf truncados.");
    }

    private static ReadOnlySpan<byte> ReadBytes(ReadOnlySpan<byte> data, ref int position)
    {
        var length = checked((int)ReadVarint(data, ref position));
        if (length < 0 || position + length > data.Length)
            throw new InvalidOperationException("Datos protobuf truncados.");
        var result = data.Slice(position, length);
        position += length;
        return result;
    }

    private static void SkipField(ReadOnlySpan<byte> data, ref int position, int wireType)
    {
        switch (wireType)
        {
            case 0:
                ReadVarint(data, ref position);
                break;
            case 1:
                position += 8;
                break;
            case 2:
                ReadBytes(data, ref position);
                break;
            case 5:
                position += 4;
                break;
            default:
                throw new InvalidOperationException("El QR contiene un tipo protobuf no compatible.");
        }
        if (position > data.Length) throw new InvalidOperationException("Datos protobuf truncados.");
    }

    private static string ToBase32(ReadOnlySpan<byte> data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;
        foreach (var current in data)
        {
            buffer = (buffer << 8) | current;
            bits += 8;
            while (bits >= 5)
            {
                output.Append(alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) output.Append(alphabet[(buffer << (5 - bits)) & 31]);
        return output.ToString();
    }
}
