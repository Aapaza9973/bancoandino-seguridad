using System.Data;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

/*
   Always Encrypted - aprovisionamiento de claves.

   T-SQL no puede crear la CEK: hay que cifrarla con la clave publica
   de la CMK, y esa clave vive en el almacen del cliente. Esta
   herramienta hace exactamente lo que hace SSMS al crear una clave:
     - toma el certificado CMK_BancoAndino de CurrentUser\My,
     - genera una CEK de 32 bytes (AES-256),
     - la cifra con RSA-OAEP usando el proveedor de almacen de
       certificados del driver,
     - registra CMK y CEK en el motor y crea dbo.ClientesAE,
     - siembra filas de ejemplo por una conexion con cifrado activo.

   Uso:
     powershell -File pki\crear-cmk.ps1
     dotnet run --project tools/AeSetup
*/

const string AsuntoCmk = "CN=CMK_BancoAndino";
const string NombreCmk = "CMK_BancoAndino";
const string NombreCek = "CEK_BancoAndino";
const string Cadena = "Server=localhost;Database=BancoAndino;Integrated Security=True;TrustServerCertificate=True;Encrypt=False";

var cadenaServidor = Environment.GetEnvironmentVariable("AE_SERVIDOR") ?? Cadena;

// ---------- 1. Certificado CMK del almacen del usuario ----------
using var almacen = new X509Store(StoreName.My, StoreLocation.CurrentUser);
almacen.Open(OpenFlags.ReadOnly);

var certificado = almacen.Certificates
    .Find(X509FindType.FindBySubjectDistinguishedName, AsuntoCmk, validOnly: false)
    .Cast<X509Certificate2>()
    .Where(c => c.HasPrivateKey)
    .OrderByDescending(c => c.NotAfter)
    .FirstOrDefault()
    ?? throw new InvalidOperationException(
        "No hay certificado " + AsuntoCmk + " en CurrentUser\\My. " +
        "Ejecuta primero: powershell -File pki\\crear-cmk.ps1");

var rutaClave = $"CurrentUser/My/{certificado.Thumbprint}";
Console.WriteLine($"CMK        : {certificado.Subject}");
Console.WriteLine($"Ruta       : {rutaClave}");
Console.WriteLine($"Vence      : {certificado.NotAfter:yyyy-MM-dd}");

// ---------- 2. CEK cifrada con RSA-OAEP ----------
var proveedor = new SqlColumnEncryptionCertificateStoreProvider();
var cek = RandomNumberGenerator.GetBytes(32);
var cekCifrada = proveedor.EncryptColumnEncryptionKey(rutaClave, "RSA_OAEP", cek);
Console.WriteLine($"CEK        : 32 bytes AES-256, cifrada con RSA-OAEP ({cekCifrada.Length} bytes)");

await using var cn = new SqlConnection(cadenaServidor);
await cn.OpenAsync();

async Task<int> EscalarAsync(string sql)
{
    await using var cmd = new SqlCommand(sql, cn);
    var v = await cmd.ExecuteScalarAsync();
    return v is null or DBNull ? 0 : Convert.ToInt32(v);
}

async Task EjecutarAsync(string sql)
{
    await using var cmd = new SqlCommand(sql, cn);
    await cmd.ExecuteNonQueryAsync();
}

// ---------- 3. Metadatos de claves en el motor ----------
if (await EscalarAsync($"SELECT COUNT(*) FROM sys.column_master_keys WHERE name = '{NombreCmk}'") == 0)
{
    await EjecutarAsync(
        $"CREATE COLUMN MASTER KEY {NombreCmk} WITH (" +
        "KEY_STORE_PROVIDER_NAME = N'MSSQL_CERTIFICATE_STORE', " +
        $"KEY_PATH = N'{rutaClave}');");
    Console.WriteLine("CMK registrada en el motor.");
}

if (await EscalarAsync($"SELECT COUNT(*) FROM sys.column_encryption_keys WHERE name = '{NombreCek}'") == 0)
{
    await EjecutarAsync(
        $"CREATE COLUMN ENCRYPTION KEY {NombreCek} WITH VALUES (" +
        $"COLUMN_MASTER_KEY = {NombreCmk}, " +
        "ALGORITHM = 'RSA_OAEP', " +
        $"ENCRYPTED_VALUE = 0x{Convert.ToHexString(cekCifrada)});");
    Console.WriteLine("CEK registrada en el motor.");
}

// ---------- 4. Tabla cifrada (la misma definicion de 16_always_encrypted.sql) ----------
var rutaSql = BuscarSql("16_always_encrypted.sql");
if (rutaSql is null)
{
    Console.WriteLine("No se encontro app/sql/16_always_encrypted.sql; ejecutalo con sqlcmd antes de sembrar.");
}
else
{
    foreach (var lote in Regex.Split(await File.ReadAllTextAsync(rutaSql), @"^\s*GO\s*$",
                 RegexOptions.Multiline | RegexOptions.IgnoreCase))
    {
        if (string.IsNullOrWhiteSpace(lote)) continue;
        await using var cmd = new SqlCommand(lote, cn);
        await cmd.ExecuteNonQueryAsync();
    }
    Console.WriteLine("Tabla y permisos de dbo.ClientesAE aplicados desde 16_always_encrypted.sql.");
}

// ---------- 5. Siembra por una conexion con cifrado activo ----------
var conCifrado = new SqlConnectionStringBuilder(cadenaServidor)
{
    ColumnEncryptionSetting = SqlConnectionColumnEncryptionSetting.Enabled
}.ConnectionString;

await using var ae = new SqlConnection(conCifrado);
await ae.OpenAsync();

int filas;
await using (var contar = new SqlCommand("SELECT COUNT(*) FROM dbo.ClientesAE;", ae))
    filas = (int)(await contar.ExecuteScalarAsync() ?? 0);

if (filas == 0)
{
    var semilla = new (string Ci, string Nombre, decimal Saldo, string Tarjeta)[]
    {
        ("8765432", "Ana Quispe",    15420.50m, "4532-1122-3344-5566"),
        ("1234567", "Luis Mamani",    8750.00m, "5489-9988-7766-1234"),
        ("9876543", "Sofia Vargas",  32100.75m, "4111-0000-1111-2222"),
        ("7654321", "Pedro Rios",     4300.00m, "6011-3344-5566-7788"),
        ("2345678", "Maria Condori",   980.25m, "4556-7788-9900-1122")
    };

    foreach (var (ci, nombre, saldo, tarjeta) in semilla)
    {
        await using var cmd = new SqlCommand(
            "INSERT INTO dbo.ClientesAE (CI, Nombre, SaldoCuenta, NumeroTarjeta) " +
            "VALUES (@ci, @nombre, @saldo, @tarjeta);", ae);

        // Tipos explicitos: con Always Encrypted el driver cifra el parametro
        // segun la definicion de la columna. Un AddWithValue manda nvarchar y
        // el motor rechaza la comparacion contra char(9).
        cmd.Parameters.Add("@ci", SqlDbType.Char, 9).Value = ci;
        cmd.Parameters.Add("@nombre", SqlDbType.NVarChar, 100).Value = nombre;
        var pSaldo = cmd.Parameters.Add("@saldo", SqlDbType.Decimal);
        pSaldo.Precision = 12;
        pSaldo.Scale = 2;
        pSaldo.Value = saldo;
        cmd.Parameters.Add("@tarjeta", SqlDbType.Char, 19).Value = tarjeta;

        await cmd.ExecuteNonQueryAsync();
    }
    Console.WriteLine($"Sembradas {semilla.Length} filas en dbo.ClientesAE.");
}
else
{
    Console.WriteLine($"dbo.ClientesAE ya tiene {filas} filas; no se siembra de nuevo.");
}

// ---------- 6. Comprobacion: en claro con cifrado, binario sin el ----------
await using (var claro = new SqlCommand("SELECT TOP 3 CI, Nombre, SaldoCuenta FROM dbo.ClientesAE ORDER BY ClienteID;", ae))
await using (var rd = await claro.ExecuteReaderAsync())
{
    Console.WriteLine("Con Column Encryption Setting=Enabled (descifra el cliente):");
    while (await rd.ReadAsync())
        Console.WriteLine($"  {rd.GetString(0)} | {rd.GetString(1)} | {rd.GetDecimal(2):N2}");
}

await using (var opaco = new SqlCommand("SELECT TOP 1 CI FROM dbo.ClientesAE;", cn))
await using (var rd = await opaco.ExecuteReaderAsync())
{
    Console.WriteLine("Sin cifrado en el cliente (lo que ve el motor y un DBA):");
    while (await rd.ReadAsync())
    {
        var bytes = (byte[])rd.GetValue(0);
        Console.WriteLine($"  varbinary({bytes.Length}) = {Convert.ToHexString(bytes)[..48]}…");
    }
}

static string? BuscarSql(string archivo)
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
    {
        var candidato = Path.Combine(dir.FullName, "app", "sql", archivo);
        if (File.Exists(candidato)) return candidato;
    }
    return null;
}
