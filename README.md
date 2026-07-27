# Vaultwarden OTP Importer

Aplicación de escritorio Windows Forms para transferir cuentas TOTP desde un QR de exportación de Google Authenticator a cuentas existentes de Vaultwarden.

## Funciones

- Lee imágenes QR de exportación de Google Authenticator.
- Muestra los TOTP encontrados sin exponer sus secretos.
- Carga las cuentas de una bóveda Vaultwarden.
- Permite seleccionar un OTP y la cuenta a la que se asociará.
- Solicita confirmación antes de sobrescribir un OTP existente.
- Procesa el QR y la conexión en paralelo.
- Reutiliza la sesión durante la ejecución para reducir tiempos de espera.

## Requisitos

- Windows 10 u 11.
- .NET 8 SDK para compilar.
- Bitwarden CLI 2026.4.2 (`bw.exe`) junto a la aplicación al ejecutarla.
- Un servidor Vaultwarden accesible mediante HTTPS.

## Compilación

```powershell
dotnet restore
dotnet build -c Release
```

Publicación autocontenida para Windows x64:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true
```

## Seguridad

- La contraseña maestra no se incluye en argumentos del proceso.
- El fichero temporal utilizado durante el login se vacía y elimina inmediatamente.
- La sesión se conserva únicamente en memoria.
- Los secretos OTP no se muestran ni se escriben en archivos.
- La sesión de Vaultwarden se cierra al cerrar la aplicación.
- Solo se admiten cuentas TOTP; las entradas HOTP se rechazan.

## Dependencias

- [ZXing.Net](https://github.com/micjahn/ZXing.Net) para leer códigos QR.
- [Bitwarden CLI](https://bitwarden.com/help/cli/) como cliente cifrado compatible con Vaultwarden.

