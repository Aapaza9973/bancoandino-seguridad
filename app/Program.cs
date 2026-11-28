using System.Data;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Collections.Concurrent;
using System.Text;
using System.Threading.Channels;
using System.Xml;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddUserSecrets<Program>(optional: true);
// Las variables de entorno mandan sobre los secretos locales: es lo que usa
// tools/verificar-ci-local.sh para apuntar las pruebas a su contenedor.
builder.Configuration.AddEnvironmentVariables();

// HTTP para el preview local y HTTPS con el certificado de desarrollo.
if (!builder.Environment.IsEnvironment("Testing"))
{
    builder.WebHost.ConfigureKestrel(o =>
    {
        o.ListenLocalhost(5080);
        o.ListenLocalhost(5443, l => l.UseHttps());
    });
}

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

// CSRF: una mutación con Origin de otro host se rechaza.
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Method is "POST" or "PUT" or "PATCH" or "DELETE")
    {
        var origen = ctx.Request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origen)
            && Uri.TryCreate(origen, UriKind.Absolute, out var u)
            && !string.Equals(u.Authority, ctx.Request.Host.Value, StringComparison.OrdinalIgnoreCase))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { error = "Origen no permitido." });
            return;
        }
    }
    await next();
});

Bd.ConnectionString = builder.Configuration.GetConnectionString("BancoAndino")
    ?? throw new InvalidOperationException(
        "Falta la cadena de conexión 'BancoAndino'. Configúrala con: " +
        "dotnet user-secrets set \"ConnectionStrings:BancoAndino\" \"Server=...\"");

// Misma cuenta y misma base, pero con Always Encrypted activo en el cliente:
// el driver pide la CEK, la descifra con la CMK del almacén y descifra las
// columnas. Sin esta opción el mismo SELECT devuelve el binario cifrado.
Bd.ConnectionStringAe = new SqlConnectionStringBuilder(Bd.ConnectionString)
{
    ColumnEncryptionSetting = SqlConnectionColumnEncryptionSetting.Enabled
}.ConnectionString;

// Política de autenticación: 5 fallos bloquean la cuenta 5 minutos y la sesión
// caduca a los 30 minutos sin uso (deslizante) y a las 8 horas (absoluta).
const int MaxIntentosFallidos = 5;
var minutosBloqueo = 5;
var vidaSesion = TimeSpan.FromMinutes(30);
var vidaAbsoluta = TimeSpan.FromHours(8);

var tablas = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
{
    ["clientes"] = "dbo.Clientes",
    ["transacciones"] = "dbo.Transacciones",
    ["empleados"] = "dbo.Empleados"
};

var columnas = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
{
    ["Clientes"] = new[] { "CI", "Email", "NumeroTarjeta", "SaldoCuenta", "Telefono" },
    ["Empleados"] = new[] { "CI", "EmailCorporativo", "Salario" }
};

var funciones = new[]
{
    "default()",
    "email()",
    "random(1, 9999)",
    "partial(0,\"XXXX-XXXX-XXXX-\",4)",
    "partial(0,\"XXXX\",4)",
    "partial(2,\"XXXXXXX\",0)"
};

var permisosValidos = new[] { "SELECT", "INSERT", "UPDATE", "DELETE" };
var accionesValidas = new[] { "GRANT", "DENY", "REVOKE" };

// Avisos en vivo: cada pestaña suscrita a /api/eventos recibe la tabla que
// cambió. Vive en el proceso, que es quien sirve la consola.
var oyentes = new ConcurrentDictionary<Guid, Channel<string>>();

void Avisar(string tabla)
{
    var aviso = System.Text.Json.JsonSerializer.Serialize(new { tabla, accion = "alta" });
    foreach (var (id, canal) in oyentes)
        if (!canal.Writer.TryWrite(aviso))
            oyentes.TryRemove(id, out _);
}

// ---------- utilidades de datos ----------
static async Task<List<Dictionary<string, object?>>> LeerAsync(SqlCommand cmd)
{
    var filas = new List<Dictionary<string, object?>>();
    using var rd = await cmd.ExecuteReaderAsync();
    do
    {
        while (await rd.ReadAsync())
        {
            var fila = new Dictionary<string, object?>();
            for (int i = 0; i < rd.FieldCount; i++)
                fila[rd.GetName(i)] = await rd.IsDBNullAsync(i) ? null : rd.GetValue(i);
            filas.Add(fila);
        }
    } while (await rd.NextResultAsync());
    return filas;
}

static async Task<List<Dictionary<string, object?>>> ConsultaAsync(string sql, params (string, object?)[] ps)
{
    await using var cn = new SqlConnection(Bd.ConnectionString);
    await cn.OpenAsync();
    await using var cmd = new SqlCommand(sql, cn);
    foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
    return await LeerAsync(cmd);
}

/// Ejecuta una consulta en el contexto del usuario de base indicado.
static async Task<List<Dictionary<string, object?>>> ConsultaComoAsync(string principal, string sql, params (string, object?)[] ps)
{
    await using var cn = new SqlConnection(Bd.ConnectionString);
    await cn.OpenAsync();
    try
    {
        await using var cmd = new SqlCommand($"EXECUTE AS USER = @__usr;\n{sql}\nREVERT;", cn);
        cmd.Parameters.AddWithValue("@__usr", principal);
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return await LeerAsync(cmd);
    }
    catch
    {
        try
        {
            await using var revert = new SqlCommand("REVERT;", cn);
            await revert.ExecuteNonQueryAsync();
        }
        catch { /* la conexión se descarta */ }
        throw;
    }
}

/// Igual que ConsultaComoAsync, pero por la conexión con Always Encrypted activo.
/// La suplantación va en un comando aparte para que sp_describe_parameter_encryption
/// resuelva los metadatos con el usuario real y no con la cuenta de la aplicación.
async Task<List<Dictionary<string, object?>>> ConsultaAeAsync(
    string? principal, string sql, Action<SqlParameterCollection>? parametros = null)
{
    await using var cn = new SqlConnection(Bd.ConnectionStringAe);
    await cn.OpenAsync();

    if (principal is not null)
    {
        await using var imp = new SqlCommand("EXECUTE AS USER = @u;", cn);
        imp.Parameters.Add("@u", SqlDbType.NVarChar, 128).Value = principal;
        await imp.ExecuteNonQueryAsync();
    }

    try
    {
        await using var cmd = new SqlCommand(sql, cn);
        parametros?.Invoke(cmd.Parameters);
        return await LeerAsync(cmd);
    }
    finally
    {
        try
        {
            await using var revert = new SqlCommand("REVERT;", cn);
            await revert.ExecuteNonQueryAsync();
        }
        catch { /* la conexión se descarta */ }
    }
}

/// Columnas que el motor le concede leer al principal, resueltas en su contexto.
static async Task<List<string>> ColumnasVisiblesAsync(string principal, string tabla)
{
    var filas = await ConsultaComoAsync(principal,
        $@"SELECT c.name AS columna
           FROM sys.columns c
           WHERE c.object_id = OBJECT_ID('{tabla}')
             AND HAS_PERMS_BY_NAME('{tabla}', 'OBJECT', 'SELECT', c.name, 'COLUMN') = 1
           ORDER BY c.column_id;");
    return filas.Select(f => (string)f["columna"]!).ToList();
}

/// Inserta como el usuario de la base (EXECUTE AS USER): el permiso lo decide
/// el motor, no la aplicación. Devuelve el identificador generado.
async Task<int> InsertarComoAsync(string principal, string sql, Action<SqlParameterCollection> parametros)
{
    await using var cn = new SqlConnection(Bd.ConnectionString);
    await cn.OpenAsync();

    await using (var imp = new SqlCommand("EXECUTE AS USER = @u;", cn))
    {
        imp.Parameters.Add("@u", SqlDbType.NVarChar, 128).Value = principal;
        await imp.ExecuteNonQueryAsync();
    }

    try
    {
        await using var cmd = new SqlCommand(sql, cn);
        parametros(cmd.Parameters);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }
    finally
    {
        try
        {
            await using var revert = new SqlCommand("REVERT;", cn);
            await revert.ExecuteNonQueryAsync();
        }
        catch { /* la conexión se descarta */ }
    }
}

static async Task EjecutarAsync(string sql, params (string, object?)[] ps)
{
    await using var cn = new SqlConnection(Bd.ConnectionString);
    await cn.OpenAsync();
    await using var cmd = new SqlCommand(sql, cn);
    foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
    await cmd.ExecuteNonQueryAsync();
}

static string? Token(HttpContext ctx)
{
    var h = ctx.Request.Headers.Authorization.ToString();
    if (h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return h[7..].Trim();
    return ctx.Request.Cookies.TryGetValue("ba_sesion", out var c) ? c : null;
}

/// El token viaja al navegador; en la base queda solo su SHA-256.
static string HuellaToken(string token)
    => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

/// Verifica PBKDF2-HMAC-SHA256 en tiempo constante.
static bool PasswordValida(string password, byte[] sal, byte[] hash, int iteraciones)
{
    var calculado = Rfc2898DeriveBytes.Pbkdf2(password, sal, iteraciones, HashAlgorithmName.SHA256, hash.Length);
    return CryptographicOperations.FixedTimeEquals(calculado, hash);
}

// La sesión vive en dbo.SesionesApp: el motor aplica la caducidad deslizante,
// la absoluta y la revocación global. Reiniciar el proceso ya no cierra sesión.
async Task<Sesion?> SesionDeAsync(HttpContext ctx)
{
    var t = Token(ctx);
    if (string.IsNullOrEmpty(t)) return null;

    var filas = await ConsultaAsync(
        "EXEC dbo.usp_SesionValidar @TokenHash, @VidaMinutos, @VidaAbsolutaHoras;",
        ("@TokenHash", HuellaToken(t)),
        ("@VidaMinutos", (int)vidaSesion.TotalMinutes),
        ("@VidaAbsolutaHoras", (int)vidaAbsoluta.TotalHours));

    if (filas.Count == 0) return null;

    var f = filas[0];
    // Renueva la cookie para que la caducidad deslizante también aplique al navegador.
    if (ctx.Request.Cookies.ContainsKey("ba_sesion"))
        ctx.Response.Cookies.Append("ba_sesion", t, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = ctx.Request.IsHttps,
            Path = "/",
            MaxAge = vidaSesion
        });

    return new Sesion((string)f["Usuario"]!, (string)f["NombreCompleto"]!,
                      (string)f["Rol"]!, (string)f["PrincipalBD"]!);
}

// ---------- autenticación ----------
app.MapPost("/api/login", async (LoginDto dto, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(dto.Usuario) || string.IsNullOrEmpty(dto.Password))
        return Results.BadRequest(new { error = "Usuario y contraseña son obligatorios." });

    var usuario = dto.Usuario.Trim();

    // 1) Estado de la cuenta. Se consulta siempre, exista o no el usuario.
    var cuenta = await ConsultaAsync(
        @"SELECT Usuario, Activo, IntentosFallidos,
                 ISNULL(DATEDIFF(SECOND, SYSUTCDATETIME(), BloqueadoHasta), 0) AS segundos_bloqueo,
                 Sal, Hash, Iteraciones, NombreCompleto, PrincipalBD, Rol
          FROM dbo.UsuariosApp WHERE Usuario = @u",
        ("@u", usuario));

    if (cuenta.Count > 0 && Convert.ToInt32(cuenta[0]["segundos_bloqueo"]) > 0)
    {
        var minutos = (Convert.ToInt32(cuenta[0]["segundos_bloqueo"]) + 59) / 60;
        return Results.Json(new
        {
            error = $"Cuenta bloqueada por intentos fallidos. Reintenta en {minutos} minuto(s).",
            bloqueado = true
        }, statusCode: 423);
    }

    var f = cuenta.Count > 0 ? cuenta[0] : null;
    var activo = f is not null && Convert.ToBoolean(f["Activo"]);

    // 2) PBKDF2 con la sal del usuario. Si el usuario no existe se verifica
    // contra una sal ficticia para no delatar su existencia por el tiempo.
    var sal = f?["Sal"] as byte[] ?? new byte[16];
    var hash = f?["Hash"] as byte[] ?? new byte[32];
    var iteraciones = f is null ? 210000 : Convert.ToInt32(f["Iteraciones"]);
    var claveValida = PasswordValida(dto.Password, sal, hash, iteraciones);

    if (f is null || !activo || !claveValida)
    {
        if (f is not null && activo)
        {
            var fallos = await ConsultaAsync(
                @"UPDATE dbo.UsuariosApp
                     SET IntentosFallidos = IntentosFallidos + 1,
                         UltimoIntento    = SYSUTCDATETIME(),
                         BloqueadoHasta   = CASE WHEN IntentosFallidos + 1 >= @max
                                                 THEN DATEADD(MINUTE, @min, SYSUTCDATETIME()) END
                     OUTPUT INSERTED.IntentosFallidos AS intentos,
                            ISNULL(DATEDIFF(SECOND, SYSUTCDATETIME(), INSERTED.BloqueadoHasta), 0) AS segundos_bloqueo
                   WHERE Usuario = @u AND Activo = 1;",
                ("@max", MaxIntentosFallidos), ("@min", minutosBloqueo), ("@u", usuario));

            if (fallos.Count > 0 && Convert.ToInt32(fallos[0]["segundos_bloqueo"]) > 0)
                return Results.Json(new
                {
                    error = $"Demasiados intentos fallidos: la cuenta queda bloqueada {minutosBloqueo} minutos.",
                    bloqueado = true
                }, statusCode: 423);

            return Results.Json(new
            {
                error = "Credenciales incorrectas o usuario inactivo.",
                intentos_restantes = fallos.Count > 0
                    ? Math.Max(0, MaxIntentosFallidos - Convert.ToInt32(fallos[0]["intentos"]))
                    : (int?)null
            }, statusCode: 401);
        }

        return Results.Json(new { error = "Credenciales incorrectas o usuario inactivo." }, statusCode: 401);
    }

    var sesion = new Sesion(
        (string)f["Usuario"]!, (string)f["NombreCompleto"]!,
        (string)f["Rol"]!, (string)f["PrincipalBD"]!);

    // Login correcto: se limpia el contador de fallos y se abre la sesión.
    await EjecutarAsync(
        "UPDATE dbo.UsuariosApp SET IntentosFallidos = 0, BloqueadoHasta = NULL WHERE Usuario = @u;",
        ("@u", sesion.Usuario));

    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
    await EjecutarAsync(
        "EXEC dbo.usp_SesionCrear @TokenHash, @Usuario, @Nombre, @Rol, @Principal, @VidaMinutos, @VidaAbsolutaHoras;",
        ("@TokenHash", HuellaToken(token)),
        ("@Usuario", sesion.Usuario),
        ("@Nombre", sesion.Nombre),
        ("@Rol", sesion.Rol),
        ("@Principal", sesion.Principal),
        ("@VidaMinutos", (int)vidaSesion.TotalMinutes),
        ("@VidaAbsolutaHoras", (int)vidaAbsoluta.TotalHours));

    // Cookie HttpOnly: el JavaScript no puede leer el token.
    ctx.Response.Cookies.Append("ba_sesion", token, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = ctx.Request.IsHttps,
        Path = "/",
        MaxAge = vidaSesion
    });

    return Results.Ok(new
    {
        usuario = sesion.Usuario, nombre = sesion.Nombre,
        rol = sesion.Rol, principal = sesion.Principal,
        expira_minutos = (int)vidaSesion.TotalMinutes
    });
});

app.MapPost("/api/logout", async (HttpContext ctx) =>
{
    var t = Token(ctx);
    if (!string.IsNullOrEmpty(t))
        await EjecutarAsync("EXEC dbo.usp_SesionCerrar @TokenHash;", ("@TokenHash", HuellaToken(t)));
    ctx.Response.Cookies.Delete("ba_sesion");
    return Results.Ok(new { ok = true });
});

app.MapGet("/api/sesion", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var roles = await ConsultaComoAsync(s.Principal,
        "SELECT r.name AS rol FROM sys.database_role_members m " +
        "JOIN sys.database_principals r ON m.role_principal_id = r.principal_id " +
        "JOIN sys.database_principals u ON m.member_principal_id = u.principal_id " +
        "WHERE u.name = USER_NAME();");

    var permisos = await ConsultaComoAsync(s.Principal,
        "SELECT DISTINCT objeto, permiso, estado FROM (SELECT 'Clientes' AS objeto, permission_name AS permiso, 'GRANT' AS estado FROM fn_my_permissions('dbo.Clientes','OBJECT') " +
        "UNION ALL SELECT 'Transacciones', permission_name, 'GRANT' FROM fn_my_permissions('dbo.Transacciones','OBJECT') " +
        "UNION ALL SELECT 'Empleados', permission_name, 'GRANT' FROM fn_my_permissions('dbo.Empleados','OBJECT')) x;");

    var unmask = await ConsultaComoAsync(s.Principal,
        "SELECT USER_NAME() AS principal, HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'UNMASK') AS unmask;");

    return Results.Ok(new
    {
        usuario = s.Usuario,
        nombre = s.Nombre,
        rol = s.Rol,
        principal = s.Principal,
        roles,
        permisos,
        unmask = unmask.Count > 0 && Convert.ToInt32(unmask[0]["unmask"]) == 1
    });
});

// ---------- datos ----------
app.MapGet("/api/datos/{tabla}", async (string tabla, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (!tablas.TryGetValue(tabla, out var nombre))
        return Results.NotFound(new { error = "Tabla no válida." });

    try
    {
        // SELECT * fallaria en cuanto una columna este denegada (error 230):
        // se piden solo las columnas que el motor autoriza a este principal.
        var visibles = await ColumnasVisiblesAsync(s.Principal, nombre);
        if (visibles.Count == 0)
            return Results.Json(new
            {
                tabla = nombre,
                principal = s.Principal,
                error = "El motor no le concede lectura sobre esta tabla."
            }, statusCode: 403);

        var todas = await ConsultaAsync(
            $"SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('{nombre}') ORDER BY column_id;");
        var ocultas = todas.Select(f => (string)f["name"]!).Except(visibles).ToList();

        var lista = string.Join(", ", visibles.Select(c => $"[{c}]"));
        // Orden por clave primaria descendente: la fila recién insertada entra
        // siempre en el TOP 100 aunque la tabla crezca.
        var clave = await ConsultaAsync(
            @"SELECT c.name AS columna
                FROM sys.indexes i
                JOIN sys.index_columns ic
                  ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.key_ordinal = 1
                JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
               WHERE i.object_id = OBJECT_ID(@tabla) AND i.is_primary_key = 1;",
            ("@tabla", nombre));
        var orden = clave.Count > 0 ? $" ORDER BY [{clave[0]["columna"]}] DESC" : "";
        var filas = await ConsultaComoAsync(s.Principal, $"SELECT TOP 100 {lista} FROM {nombre}{orden};");
        // El alta se ofrece solo si el motor concede INSERT a este principal.
        var puede = await ConsultaComoAsync(s.Principal,
            $"SELECT HAS_PERMS_BY_NAME('{nombre}', 'OBJECT', 'INSERT') AS puede;");
        return Results.Ok(new
        {
            tabla = nombre, principal = s.Principal, filas, columnas_ocultas = ocultas,
            puede_insertar = puede.Count > 0 && Convert.ToInt32(puede[0]["puede"]) == 1
        });
    }
    catch (SqlException ex)
    {
        return Results.Json(new
        {
            tabla = nombre,
            principal = s.Principal,
            error = ex.Message,
            numero = ex.Number
        }, statusCode: 403);
    }
});

app.MapGet("/api/auditoria", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol is not ("dba" or "auditor"))
        return Results.Json(new { error = "Solo auditoría y administración pueden ver el registro." }, statusCode: 403);

    // Lector firmado por certificado: la app no tiene CONTROL SERVER.
    var filas = await ConsultaAsync("EXEC master.dbo.usp_LeerAuditoria @Top = 200;");
    return Results.Ok(new { filas });
});

// ---------- metadatos del modelo (cierre B5) ----------
// El auditor ve la ACL, las máscaras y las columnas en su propio contexto:
// rol_auditor tiene VIEW DEFINITION (18_metadatos.sql). No obtiene SELECT en
// claro, ni CONTROL, ni permiso para abrir la CMK de Always Encrypted.
app.MapGet("/api/metadatos", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol is not ("auditor" or "dba"))
        return Results.Json(new { error = "Solo auditoría y administración ven los metadatos." }, statusCode: 403);

    var alcance = await ConsultaComoAsync(s.Principal,
        "SELECT HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION') AS view_definition, " +
        "HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONTROL') AS control;");

    var mascaras = await ConsultaComoAsync(s.Principal,
        @"SELECT OBJECT_NAME(mc.object_id) AS tabla, mc.name AS columna,
                 mc.masking_function AS funcion
          FROM sys.masked_columns mc
          ORDER BY tabla, columna;");

    var permisos = await ConsultaComoAsync(s.Principal,
        @"SELECT dp.name AS principal, p.class_desc AS ambito,
                 p.permission_name AS permiso, p.state_desc AS estado,
                 ISNULL(OBJECT_NAME(p.major_id), '(base de datos)') AS objeto,
                 COL_NAME(p.major_id, p.minor_id) AS columna
          FROM sys.database_permissions p
          JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
          WHERE dp.is_fixed_role = 0 AND dp.name NOT IN ('dbo', 'guest', 'public')
          ORDER BY dp.name, p.permission_name, objeto, columna;");

    var columnasModelo = await ConsultaComoAsync(s.Principal,
        @"SELECT OBJECT_NAME(c.object_id) AS tabla, c.name AS columna,
                 TYPE_NAME(c.user_type_id) AS tipo, c.max_length AS bytes,
                 c.is_nullable AS nulo, c.encryption_type_desc AS cifrado
          FROM sys.columns c
          WHERE OBJECTPROPERTY(c.object_id, 'IsUserTable') = 1
            AND OBJECT_NAME(c.object_id) IN ('Clientes','Empleados','Transacciones','ClientesAE')
          ORDER BY tabla, c.column_id;");

    var roles = await ConsultaComoAsync(s.Principal,
        @"SELECT r.name AS rol, u.name AS miembro
          FROM sys.database_role_members m
          JOIN sys.database_principals r ON m.role_principal_id = r.principal_id
          JOIN sys.database_principals u ON m.member_principal_id = u.principal_id
          ORDER BY r.name, u.name;");

    var a = alcance.Count > 0 ? alcance[0] : null;
    return Results.Ok(new
    {
        principal = s.Principal,
        rol = s.Rol,
        view_definition = a is not null && Convert.ToInt32(a["view_definition"]) == 1,
        control = a is not null && Convert.ToInt32(a["control"]) == 1,
        mascaras,
        permisos,
        columnas = columnasModelo,
        roles
    });
});

// ---------- administración (solo dba) ----------
app.MapGet("/api/admin/estado", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    var mascaras = await ConsultaAsync(
        @"SELECT OBJECT_NAME(mc.object_id) AS tabla, mc.name AS columna, mc.masking_function AS funcion
          FROM sys.masked_columns mc ORDER BY tabla, columna;");

    var usuarios = await ConsultaAsync(
        @"SELECT dp.name AS principal, dp.type_desc AS tipo,
                 ISNULL(r.name,'(sin rol)') AS rol, dp.create_date
          FROM sys.database_principals dp
          LEFT JOIN sys.database_role_members m ON dp.principal_id = m.member_principal_id
          LEFT JOIN sys.database_principals r ON m.role_principal_id = r.principal_id
          WHERE dp.type IN ('S','R') AND dp.is_fixed_role = 0 AND dp.name NOT IN ('dbo','guest')
          ORDER BY dp.type_desc, dp.name;");

    var permisos = await ConsultaAsync(
        @"SELECT dp.name AS principal, p.permission_name AS permiso, p.state_desc AS estado,
                 ISNULL(OBJECT_NAME(p.major_id),'(base de datos)') AS objeto,
                 COL_NAME(p.major_id, p.minor_id) AS columna
          FROM sys.database_permissions p
          JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
          WHERE dp.type IN ('S','R') AND dp.is_fixed_role = 0 AND dp.name <> 'dbo'
            AND p.class = 1 AND OBJECTPROPERTY(p.major_id,'IsUserTable') = 1
          ORDER BY dp.name, p.permission_name, objeto, columna;");

    var appUsuarios = await ConsultaAsync(
        "SELECT Usuario, NombreCompleto, PrincipalBD, Rol, Activo FROM dbo.UsuariosApp ORDER BY Rol, Usuario;");

    // La app no tiene SELECT sobre SesionesApp: cuenta por el procedimiento.
    var sesionesActivas = await ConsultaAsync(
        "EXEC dbo.usp_SesionContar @VidaMinutos, @VidaAbsolutaHoras;",
        ("@VidaMinutos", (int)vidaSesion.TotalMinutes),
        ("@VidaAbsolutaHoras", (int)vidaAbsoluta.TotalHours));

    return Results.Ok(new
    {
        mascaras, usuarios, permisos, appUsuarios,
        sesiones = sesionesActivas.Count > 0 ? sesionesActivas[0]["vigentes"] : 0
    });
});

app.MapPost("/api/admin/permiso", async (PermisoDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    if (!accionesValidas.Contains(dto.Accion?.ToUpperInvariant()))
        return Results.BadRequest(new { error = "Acción no válida (GRANT, DENY o REVOKE)." });
    if (!permisosValidos.Contains(dto.Permiso?.ToUpperInvariant()))
        return Results.BadRequest(new { error = "Permiso no válido." });
    if (!tablas.TryGetValue(dto.Tabla ?? "", out var tabla))
        return Results.BadRequest(new { error = "Tabla no válida." });
    if (!System.Text.RegularExpressions.Regex.IsMatch(dto.Principal ?? "", @"^[A-Za-z_][A-Za-z0-9_]{0,29}$"))
        return Results.BadRequest(new { error = "Principal no válido." });

    try
    {
        // El procedimiento corre como el dueno y valida la entrada; la
        // aplicacion no tiene CONTROL sobre la base.
        var filas = await ConsultaAsync(
            "EXEC dbo.usp_AdminPermiso @accion, @permiso, @tabla, @principal;",
            ("@accion", dto.Accion), ("@permiso", dto.Permiso),
            ("@tabla", dto.Tabla), ("@principal", dto.Principal));
        return Results.Ok(new { ok = true, ejecutado = filas.Count > 0 ? filas[0]["ejecutado"] : null });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/admin/mascara", async (MascaraDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    var tabla = dto.Tabla ?? "";
    if (!columnas.TryGetValue(tabla, out var cols) || !cols.Contains(dto.Columna ?? ""))
        return Results.BadRequest(new { error = "Tabla o columna no válida." });

    if (!string.IsNullOrEmpty(dto.Funcion) && !funciones.Contains(dto.Funcion))
        return Results.BadRequest(new { error = "Función de enmascaramiento no válida." });

    try
    {
        var filas = await ConsultaAsync(
            "EXEC dbo.usp_AdminMascara @tabla, @columna, @funcion;",
            ("@tabla", tabla), ("@columna", dto.Columna), ("@funcion", dto.Funcion ?? ""));
        return Results.Ok(new { ok = true, ejecutado = filas.Count > 0 ? filas[0]["ejecutado"] : null });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/admin/usuario", async (UsuarioAppDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    await EjecutarAsync("UPDATE dbo.UsuariosApp SET Activo = @a WHERE Usuario = @u;",
        ("@a", dto.Activo), ("@u", dto.Usuario));
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/admin/revocar-sesiones", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    // Revocación global en la tabla: alcanza a otros procesos y a otros nodos.
    var filas = await ConsultaAsync(
        "EXEC dbo.usp_SesionRevocarTodas @VidaMinutos, @VidaAbsolutaHoras;",
        ("@VidaMinutos", (int)vidaSesion.TotalMinutes),
        ("@VidaAbsolutaHoras", (int)vidaAbsoluta.TotalHours));
    var revocadas = filas.Count > 0 ? Convert.ToInt32(filas[0]["revocadas"]) : 0;
    ctx.Response.Cookies.Delete("ba_sesion");
    return Results.Ok(new { ok = true, revocadas });
});

// ---------- cifrado en reposo (TDE) ----------
app.MapGet("/api/cifrado", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var tde = await ConsultaAsync(
        @"SELECT dek.encryption_state_desc AS estado, dek.percent_complete AS avance,
                 dek.key_algorithm AS algoritmo, dek.key_length AS longitud
          FROM sys.dm_database_encryption_keys dek
          WHERE dek.database_id = DB_ID('BancoAndino');");

    var certTde = await ConsultaAsync(
        @"SELECT name, subject, CONVERT(varchar(10), expiry_date, 23) AS vence,
                 pvt_key_encryption_type_desc AS clave_privada
          FROM master.sys.certificates WHERE name = 'CertBancoAndino';");

    var certFirma = await ConsultaAsync(
        @"SELECT name, subject, CONVERT(varchar(10), expiry_date, 23) AS vence
          FROM sys.certificates WHERE name = 'CertTransacciones';");

    var docs = await ConsultaAsync("SELECT COUNT(*) AS firmados FROM dbo.TransaccionesFirmadas;");

    return Results.Ok(new
    {
        tde = tde.Count > 0 ? tde[0] : null,
        certTde = certTde.Count > 0 ? certTde[0] : null,
        certFirma = certFirma.Count > 0 ? certFirma[0] : null,
        firmados = docs.Count > 0 ? docs[0]["firmados"] : 0,
        rol = s.Rol
    });
});

app.MapPost("/api/cifrado/backup-certificado", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    var sello = DateTime.Now.ToString("yyyyMMdd_HHmmss");
    var cer = $@"C:\CertBackup\CertBancoAndino_{sello}.cer";
    var pvk = $@"C:\CertBackup\CertBancoAndino_{sello}_PrivKey.pvk";

    try
    {
        await EjecutarAsync(
            $"USE master; BACKUP CERTIFICATE CertBancoAndino TO FILE = '{cer}' " +
            $"WITH PRIVATE KEY (FILE = '{pvk}', ENCRYPTION BY PASSWORD = 'BackupCert_BancoAndino2026!');");
        return Results.Ok(new { ok = true, archivos = new[] { cer, pvk } });
    }
    catch (SqlException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// ---------- firma digital de transacciones ----------
app.MapGet("/api/firma", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var filas = await ConsultaAsync(
        @"SELECT DocID, Referencia, ClienteID, Monto, Tipo,
                 CONVERT(varchar(19), FechaFirma, 120) AS fecha_firma,
                 FirmadoPor, FirmaValida, Integridad
          FROM dbo.vw_EstadoFirmas ORDER BY DocID DESC;");
    return Results.Ok(new { filas, rol = s.Rol });
});

// XMLDSig con un certificado emitido por la CA de pki/crear-pki.ps1: el PFX
// aporta la clave privada y la cadena se valida contra el .cer de la raíz.
static (X509Certificate2 Cert, X509Certificate2? Raiz, bool Efimero) CertificadoDeFirma(IConfiguration cfg)
{
    var pfx = BuscarArchivo(cfg["Firma:Certificado"] ?? "pki/firma-bancoandino.pfx");
    var raiz = BuscarArchivo(cfg["Firma:Raiz"] ?? "pki/BancoAndino-RootCA.cer");
    var clave = cfg["Firma:Password"] ?? "Firma_BancoAndino_2026!";

    if (pfx is not null)
    {
        var cert = X509CertificateLoader.LoadPkcs12FromFile(pfx, clave, X509KeyStorageFlags.EphemeralKeySet);
        var ancla = raiz is not null ? X509CertificateLoader.LoadCertificateFromFile(raiz) : null;
        return (cert, ancla, false);
    }

    using var rsa = RSA.Create(2048);
    var solicitud = new CertificateRequest(
        "CN=BancoAndino XMLDSig (efimero, sin CA)", rsa,
        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    return (solicitud.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1)), null, true);
}

static bool CadenaConfiable(X509Certificate2 cert, X509Certificate2? raiz)
{
    if (raiz is null) return false;
    using var cadena = new X509Chain();
    cadena.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
    cadena.ChainPolicy.CustomTrustStore.Add(raiz);
    cadena.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    cadena.ChainPolicy.DisableCertificateDownloads = true;
    return cadena.Build(cert);
}

/// Busca un archivo del repositorio subiendo desde el directorio de ejecución,
/// para que funcione igual con dotnet run, con el binario y en las pruebas.
static string? BuscarArchivo(string relativo)
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
    {
        var candidato = Path.Combine(dir.FullName, relativo.Replace('/', Path.DirectorySeparatorChar));
        if (File.Exists(candidato)) return candidato;
    }
    return null;
}

app.MapGet("/api/firma/xmldsig", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var id = "TX-" + Guid.NewGuid().ToString("N")[..12];
    var doc = new XmlDocument { PreserveWhitespace = true };
    var raiz = doc.CreateElement("Transaccion");
    raiz.SetAttribute("Id", id);
    foreach (var (etiqueta, valor) in new[]
    {
        ("Referencia", id),
        ("ClienteID", "1"),
        ("Monto", "15420.50"),
        ("Tipo", "TRANSFERENCIA"),
        ("Fecha", DateTime.UtcNow.ToString("s"))
    })
    {
        var e = doc.CreateElement(etiqueta);
        e.InnerText = valor;
        raiz.AppendChild(e);
    }
    doc.AppendChild(raiz);

    var (cert, ancla, efimero) = CertificadoDeFirma(app.Configuration);
    using var certificado = cert;
    using var raizCa = ancla;

    var firmado = new SignedXml(doc) { SigningKey = certificado.GetRSAPrivateKey()! };
    firmado.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
    firmado.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

    var referencia = new Reference("#" + id) { DigestMethod = SignedXml.XmlDsigSHA256Url };
    referencia.AddTransform(new XmlDsigEnvelopedSignatureTransform());
    referencia.AddTransform(new XmlDsigExcC14NTransform());
    firmado.AddReference(referencia);
    firmado.ComputeSignature();

    doc.DocumentElement!.AppendChild(doc.ImportNode(firmado.GetXml(), true));

    var verificador = new SignedXml(doc);
    verificador.LoadXml((XmlElement)doc.GetElementsByTagName("Signature")[0]!);
    var valida = verificador.CheckSignature(certificado, true);
    var cadenaValida = CadenaConfiable(certificado, raizCa);

    return Results.Ok(new
    {
        valida,
        cadena_valida = cadenaValida,
        origen = efimero ? "efímero (sin CA)" : "CA local BancoAndino",
        emisor = certificado.Issuer,
        raiz = raizCa?.Subject,
        certificado = certificado.Subject,
        vence = certificado.NotAfter.ToString("yyyy-MM-dd"),
        huella = certificado.Thumbprint,
        algoritmo = "XMLDSig enveloped · RSA-SHA256 · Exclusive C14N",
        xml = doc.OuterXml
    });
});

app.MapPost("/api/firma/firmar", async (FirmaDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    if (dto.ClienteId <= 0) return Results.BadRequest(new { error = "Cliente no válido." });
    if (dto.Monto <= 0) return Results.BadRequest(new { error = "El monto debe ser mayor a cero." });
    if (string.IsNullOrWhiteSpace(dto.Tipo) || dto.Tipo.Length > 20)
        return Results.BadRequest(new { error = "Tipo de transacción no válido." });

    await using var cn = new SqlConnection(Bd.ConnectionString);
    await cn.OpenAsync();
    await using var cmd = new SqlCommand("dbo.usp_FirmarTransaccion", cn) { CommandType = System.Data.CommandType.StoredProcedure };
    cmd.Parameters.AddWithValue("@ClienteID", dto.ClienteId);
    cmd.Parameters.AddWithValue("@Monto", dto.Monto);
    cmd.Parameters.AddWithValue("@Tipo", dto.Tipo);
    var outId = new SqlParameter("@DocID", System.Data.SqlDbType.Int) { Direction = System.Data.ParameterDirection.Output };
    cmd.Parameters.Add(outId);
    await cmd.ExecuteNonQueryAsync();

    return Results.Ok(new { ok = true, docId = outId.Value });
});

app.MapPost("/api/firma/alterar", async (DocDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Solo administración puede alterar un documento (demostración)." }, statusCode: 403);

    await EjecutarAsync("EXEC dbo.usp_AlterarTransaccion @id;", ("@id", dto.DocId));
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/firma/restaurar", async (DocDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Solo administración puede restaurar (demostración)." }, statusCode: 403);

    await EjecutarAsync("EXEC dbo.usp_RestaurarTransaccion @id;", ("@id", dto.DocId));
    return Results.Ok(new { ok = true });
});

// ---------- cifrado por columna (tarjeta y CVV) ----------
app.MapGet("/api/columnas", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    try
    {
        var filas = await ConsultaComoAsync(s.Principal,
            @"SELECT TarjetaID, ClienteID, Ultimos4,
                     DATALENGTH(NumeroCifrado) AS bytes_numero,
                     DATALENGTH(CVVCifrado) AS bytes_cvv,
                     CONVERT(varchar(19), FechaAlta, 120) AS alta
              FROM dbo.TarjetasCifradas ORDER BY TarjetaID;");
        return Results.Ok(new { filas, principal = s.Principal, rol = s.Rol });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message, principal = s.Principal }, statusCode: 403);
    }
});

app.MapPost("/api/columnas/guardar", async (TarjetaDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var numero = (dto.Numero ?? "").Trim();
    var cvv = (dto.Cvv ?? "").Trim();
    if (numero.Length < 12 || numero.Length > 19)
        return Results.BadRequest(new { error = "El número de tarjeta debe tener entre 12 y 19 caracteres." });
    if (cvv.Length is < 3 or > 4)
        return Results.BadRequest(new { error = "El CVV debe tener 3 o 4 dígitos." });

    await using var cn = new SqlConnection(Bd.ConnectionString);
    await cn.OpenAsync();
    await using var cmd = new SqlCommand("dbo.usp_GuardarTarjeta", cn) { CommandType = System.Data.CommandType.StoredProcedure };
    cmd.Parameters.AddWithValue("@ClienteID", dto.ClienteId);
    cmd.Parameters.AddWithValue("@Numero", numero);
    cmd.Parameters.AddWithValue("@CVV", cvv);
    var outId = new SqlParameter("@TarjetaID", System.Data.SqlDbType.Int) { Direction = System.Data.ParameterDirection.Output };
    cmd.Parameters.Add(outId);
    await cmd.ExecuteNonQueryAsync();

    return Results.Ok(new { ok = true, tarjetaId = outId.Value });
});

app.MapPost("/api/columnas/descifrar", async (TarjetaIdDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (dto.TarjetaId <= 0) return Results.BadRequest(new { error = "Tarjeta no válida." });

    try
    {
        var filas = await ConsultaComoAsync(s.Principal, $"EXEC dbo.usp_DescifrarTarjeta {dto.TarjetaId};");
        var f = filas.Count > 0 ? filas[0] : null;
        return Results.Ok(new
        {
            ok = true,
            como = "usuario",
            principal = s.Principal,
            numero = f?["Numero"],
            cvv = f?["CVV"]
        });
    }
    catch (SqlException ex)
    {
        // El motor negó abrir la clave: no hay atajo ni lectura como dueño.
        return Results.Json(new { denegado = true, principal = s.Principal, error = ex.Message, numero = (string?)null }, statusCode: 403);
    }
});

// ---------- Always Encrypted ----------
// La tabla dbo.ClientesAE guarda CI (determinista), nombre, saldo y tarjeta
// (aleatorios) cifrados. El motor nunca ve el texto claro: lo descifra el
// driver con la CEK, que se abre con la CMK del almacén del cliente.
app.MapGet("/api/ae/estado", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var cmk = await ConsultaAsync(
        "SELECT name, key_store_provider_name AS proveedor, key_path AS ruta FROM sys.column_master_keys;");
    var cek = await ConsultaAsync(
        @"SELECT cek.name AS nombre, cmk.name AS clave_maestra,
                 v.encryption_algorithm_name AS algoritmo,
                 DATALENGTH(v.encrypted_value) AS bytes_cifrados
          FROM sys.column_encryption_keys cek
          JOIN sys.column_encryption_key_values v ON v.column_encryption_key_id = cek.column_encryption_key_id
          JOIN sys.column_master_keys cmk         ON cmk.column_master_key_id = v.column_master_key_id;");
    var columnasAe = await ConsultaAsync(
        @"SELECT c.name AS columna, c.encryption_type_desc AS tipo,
                 c.encryption_algorithm_name AS algoritmo, c.collation_name AS collation
          FROM sys.columns c
          WHERE c.object_id = OBJECT_ID('dbo.ClientesAE') AND c.encryption_type IS NOT NULL
          ORDER BY c.column_id;");

    var disponible = cek.Count > 0 && columnasAe.Count > 0;
    if (!disponible)
        return Results.Ok(new
        {
            disponible,
            principal = s.Principal,
            rol = s.Rol,
            cmk, cek,
            columnas = columnasAe,
            motivo = "Faltan CMK/CEK o la tabla dbo.ClientesAE: ejecuta pki/crear-cmk.ps1 y tools/AeSetup."
        });

    if (s.Rol is not ("cajero" or "riesgos"))
        return Results.Json(new
        {
            disponible,
            principal = s.Principal,
            rol = s.Rol,
            cmk, cek,
            columnas = columnasAe,
            cifrada = (object?)null,
            descifrada = (object?)null,
            error = "Este rol no tiene SELECT sobre dbo.ClientesAE: el motor niega la lectura."
        }, statusCode: 403);

    object? cifrada = null;
    object? descifrada = null;
    string? error = null;

    try
    {
        // Misma cuenta, misma consulta, Always Encrypted desactivado:
        // el driver entrega el binario, sin clave ni descifrado.
        cifrada = await ConsultaComoAsync(s.Principal,
            "SELECT TOP 5 ClienteID, CI, Nombre, SaldoCuenta FROM dbo.ClientesAE ORDER BY ClienteID;");

        // Con Always Encrypted activo el driver descifra en el cliente.
        descifrada = await ConsultaAeAsync(s.Principal,
            "SELECT TOP 5 ClienteID, CI, Nombre, SaldoCuenta FROM dbo.ClientesAE ORDER BY ClienteID;");
    }
    catch (SqlException ex)
    {
        error = ex.Message;
    }

    return Results.Ok(new
    {
        disponible,
        principal = s.Principal,
        rol = s.Rol,
        cmk, cek,
        columnas = columnasAe,
        cifrada,
        descifrada,
        error
    });
});

app.MapGet("/api/ae/clientes", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol is not ("cajero" or "riesgos"))
        return Results.Json(new { error = "Solo cajero y riesgos leen la tabla cifrada." }, statusCode: 403);

    try
    {
        var filas = await ConsultaAeAsync(s.Principal,
            @"SELECT ClienteID, CI, Nombre, SaldoCuenta, NumeroTarjeta,
                     CONVERT(varchar(19), FechaAlta, 120) AS alta
              FROM dbo.ClientesAE ORDER BY ClienteID;");
        return Results.Ok(new { filas, principal = s.Principal });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 403);
    }
});

app.MapGet("/api/ae/buscar", async (string ci, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol is not ("cajero" or "riesgos"))
        return Results.Json(new { error = "Solo cajero y riesgos consultan la tabla cifrada." }, statusCode: 403);
    if (string.IsNullOrWhiteSpace(ci) || ci.Trim().Length > 9)
        return Results.BadRequest(new { error = "CI no válida." });

    try
    {
        // La igualdad solo es posible porque CI es determinista. El parámetro
        // lleva el tipo de la columna; con nvarchar el motor rechaza comparar.
        var filas = await ConsultaAeAsync(s.Principal,
            "SELECT ClienteID, CI, Nombre, SaldoCuenta FROM dbo.ClientesAE WHERE CI = @ci;",
            ps =>
            {
                var p = ps.Add("@ci", SqlDbType.Char, 9);
                p.Value = ci.Trim();
                p.ForceColumnEncryption = true;
            });
        return Results.Ok(new { ci = ci.Trim(), filas, principal = s.Principal });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/ae/guardar", async (ClienteAeDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol is not ("cajero" or "riesgos"))
        return Results.Json(new { error = "Solo cajero y riesgos escriben en la tabla cifrada." }, statusCode: 403);

    var ci = (dto.Ci ?? "").Trim();
    var nombre = (dto.Nombre ?? "").Trim();
    var tarjeta = (dto.Tarjeta ?? "").Trim();
    if (ci.Length is < 7 or > 9) return Results.BadRequest(new { error = "La CI debe tener entre 7 y 9 caracteres." });
    if (nombre.Length is < 3 or > 100) return Results.BadRequest(new { error = "El nombre debe tener entre 3 y 100 caracteres." });
    if (dto.Saldo < 0) return Results.BadRequest(new { error = "El saldo no puede ser negativo." });
    if (tarjeta.Length is < 12 or > 19) return Results.BadRequest(new { error = "El número de tarjeta debe tener entre 12 y 19 caracteres." });

    try
    {
        await using var cn = new SqlConnection(Bd.ConnectionStringAe);
        await cn.OpenAsync();

        await using (var imp = new SqlCommand("EXECUTE AS USER = @u;", cn))
        {
            imp.Parameters.Add("@u", SqlDbType.NVarChar, 128).Value = s.Principal;
            await imp.ExecuteNonQueryAsync();
        }

        try
        {
            await using var cmd = new SqlCommand(
                "SET NOCOUNT ON; " +
                "INSERT INTO dbo.ClientesAE (CI, Nombre, SaldoCuenta, NumeroTarjeta) " +
                "VALUES (@ci, @nombre, @saldo, @tarjeta); " +
                "SELECT CAST(SCOPE_IDENTITY() AS INT);", cn);

            cmd.Parameters.Add("@ci", SqlDbType.Char, 9).Value = ci;
            cmd.Parameters.Add("@nombre", SqlDbType.NVarChar, 100).Value = nombre;
            var saldo = cmd.Parameters.Add("@saldo", SqlDbType.Decimal);
            saldo.Precision = 12;
            saldo.Scale = 2;
            saldo.Value = dto.Saldo;
            cmd.Parameters.Add("@tarjeta", SqlDbType.Char, 19).Value = tarjeta;

            var id = await cmd.ExecuteScalarAsync();
            return Results.Ok(new { ok = true, clienteId = id, cifrado = "Always Encrypted" });
        }
        finally
        {
            try
            {
                await using var revert = new SqlCommand("REVERT;", cn);
                await revert.ExecuteNonQueryAsync();
            }
            catch { /* la conexión se descarta */ }
        }
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

// ---------- altas de clientes y empleados ----------
// El INSERT viaja como el principal de la sesión: sin INSERT en la tabla, el
// motor responde 229 y se devuelve 403. Cada alta confirmada se anuncia a las
// pestañas abiertas para que las listas se refresquen sin recargar.
app.MapPost("/api/clientes", async (ClienteDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var nombre = (dto.Nombre ?? "").Trim();
    var ci = (dto.Ci ?? "").Trim();
    var email = (dto.Email ?? "").Trim();
    var telefono = (dto.Telefono ?? "").Trim();
    var tarjeta = (dto.Tarjeta ?? "").Trim();

    if (nombre.Length is < 3 or > 100)
        return Results.BadRequest(new { error = "El nombre debe tener entre 3 y 100 caracteres." });
    if (ci.Length is < 7 or > 9 || !ci.All(char.IsDigit))
        return Results.BadRequest(new { error = "La CI debe tener entre 7 y 9 dígitos." });
    if (email.Length is < 5 or > 150 || !email.Contains('@'))
        return Results.BadRequest(new { error = "El email no es válido." });
    if (telefono.Length != 8 || !telefono.All(char.IsDigit))
        return Results.BadRequest(new { error = "El teléfono debe tener 8 dígitos." });
    if (tarjeta.Length is < 12 or > 19 || !tarjeta.All(c => char.IsDigit(c) || c == '-'))
        return Results.BadRequest(new { error = "La tarjeta debe tener entre 12 y 19 caracteres (dígitos y guiones)." });
    if (dto.Saldo < 0 || dto.Saldo > 9_999_999_999.99m)
        return Results.BadRequest(new { error = "El saldo debe estar entre 0 y 9.999.999.999,99." });

    try
    {
        var id = await InsertarComoAsync(s.Principal,
            @"SET NOCOUNT ON;
              INSERT INTO dbo.Clientes (Nombre, CI, Email, Telefono, NumeroTarjeta, SaldoCuenta)
              OUTPUT INSERTED.ClienteID
              VALUES (@nombre, @ci, @email, @telefono, @tarjeta, @saldo);",
            ps =>
            {
                ps.Add("@nombre", SqlDbType.NVarChar, 100).Value = nombre;
                ps.Add("@ci", SqlDbType.Char, 9).Value = ci;
                ps.Add("@email", SqlDbType.NVarChar, 150).Value = email;
                ps.Add("@telefono", SqlDbType.Char, 8).Value = telefono;
                ps.Add("@tarjeta", SqlDbType.Char, 19).Value = tarjeta;
                var saldo = ps.Add("@saldo", SqlDbType.Decimal);
                saldo.Precision = 12;
                saldo.Scale = 2;
                saldo.Value = dto.Saldo;
            });

        Avisar("dbo.Clientes");
        return Results.Created("/api/datos/clientes", new { ok = true, clienteId = id, tabla = "dbo.Clientes" });
    }
    catch (SqlException ex) when (ex.Number is 229 or 230)
    {
        return Results.Json(new { error = ex.Message, principal = s.Principal }, statusCode: 403);
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/empleados", async (EmpleadoDto dto, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var nombre = (dto.Nombre ?? "").Trim();
    var ci = (dto.Ci ?? "").Trim();
    var cargo = (dto.Cargo ?? "").Trim();
    var email = (dto.Email ?? "").Trim();

    if (nombre.Length is < 3 or > 100)
        return Results.BadRequest(new { error = "El nombre debe tener entre 3 y 100 caracteres." });
    if (ci.Length is < 7 or > 9 || !ci.All(char.IsDigit))
        return Results.BadRequest(new { error = "La CI debe tener entre 7 y 9 dígitos." });
    if (cargo.Length is < 3 or > 60)
        return Results.BadRequest(new { error = "El cargo debe tener entre 3 y 60 caracteres." });
    if (email.Length is < 5 or > 150 || !email.Contains('@'))
        return Results.BadRequest(new { error = "El email corporativo no es válido." });
    if (dto.Salario <= 0 || dto.Salario > 99_999_999.99m)
        return Results.BadRequest(new { error = "El salario debe ser mayor a cero y menor a 100.000.000." });

    try
    {
        var id = await InsertarComoAsync(s.Principal,
            @"SET NOCOUNT ON;
              INSERT INTO dbo.Empleados (Nombre, CI, Cargo, Salario, EmailCorporativo)
              OUTPUT INSERTED.EmpleadoID
              VALUES (@nombre, @ci, @cargo, @salario, @email);",
            ps =>
            {
                ps.Add("@nombre", SqlDbType.NVarChar, 100).Value = nombre;
                ps.Add("@ci", SqlDbType.Char, 9).Value = ci;
                ps.Add("@cargo", SqlDbType.NVarChar, 60).Value = cargo;
                var salario = ps.Add("@salario", SqlDbType.Decimal);
                salario.Precision = 10;
                salario.Scale = 2;
                salario.Value = dto.Salario;
                ps.Add("@email", SqlDbType.NVarChar, 150).Value = email;
            });

        Avisar("dbo.Empleados");
        return Results.Created("/api/datos/empleados", new { ok = true, empleadoId = id, tabla = "dbo.Empleados" });
    }
    catch (SqlException ex) when (ex.Number is 229 or 230)
    {
        return Results.Json(new { error = ex.Message, principal = s.Principal }, statusCode: 403);
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

// ---------- avisos en vivo (Server-Sent Events) ----------
// Una conexión por pestaña; el servidor empuja el nombre de la tabla cuando hay
// un alta. Un latido cada 20 s mantiene viva la conexión y detecta al cliente.
app.MapGet("/api/eventos", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null)
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await ctx.Response.WriteAsJsonAsync(new { error = "No autenticado." });
        return;
    }

    ctx.Response.ContentType = "text/event-stream";
    ctx.Response.Headers.CacheControl = "no-cache";
    ctx.Response.Headers["X-Accel-Buffering"] = "no";

    var canal = Channel.CreateBounded<string>(new BoundedChannelOptions(16)
    {
        FullMode = BoundedChannelFullMode.DropOldest
    });
    var id = Guid.NewGuid();
    oyentes[id] = canal;

    try
    {
        await ctx.Response.WriteAsync(": conectado\n\n");
        await ctx.Response.Body.FlushAsync();

        while (!ctx.RequestAborted.IsCancellationRequested)
        {
            string? aviso = null;
            using (var espera = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted))
            {
                espera.CancelAfter(TimeSpan.FromSeconds(20));
                try { aviso = await canal.Reader.ReadAsync(espera.Token); }
                catch (OperationCanceledException) when (!ctx.RequestAborted.IsCancellationRequested) { }
            }

            await ctx.Response.WriteAsync(aviso is null
                ? ": latido\n\n"
                : $"event: cambio\ndata: {aviso}\n\n");
            await ctx.Response.Body.FlushAsync();
        }
    }
    catch (OperationCanceledException) { }
    catch (IOException) { }
    finally
    {
        oyentes.TryRemove(id, out _);
        canal.Writer.TryComplete();
    }
});

// ---------- demostraciones de laboratorio ----------

// Inferencia por WHERE: el predicado usa el saldo real aunque la salida
// venga enmascarada. Devuelve cuántos clientes superan el umbral.
app.MapGet("/api/demo/inferencia", async (int clienteId, decimal umbral, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (clienteId <= 0 || umbral < 0)
        return Results.BadRequest(new { error = "Cliente o umbral no válido." });

    try
    {
        var u = umbral.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var filas = await ConsultaComoAsync(s.Principal,
            $"SELECT COUNT(*) AS coincide FROM dbo.Clientes WHERE ClienteID = {clienteId} AND SaldoCuenta >= {u};");
        return Results.Ok(new
        {
            clienteId, umbral, principal = s.Principal,
            coincide = filas.Count > 0 ? filas[0]["coincide"] : 0
        });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message, principal = s.Principal }, statusCode: 403);
    }
});

// SQLi: el mismo filtro por la ruta vulnerable y por la parametrizada.
app.MapGet("/api/demo/sqli", async (string? filtro, HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Solo administración puede ejecutar la demostración." }, statusCode: 403);

    var f = string.IsNullOrWhiteSpace(filtro) ? "Ana Quispe" : filtro!;
    try
    {
        var vulnerable = await ConsultaComoAsync(s.Principal,
            "EXEC dbo.usp_BuscarClienteVulnerable @Nombre = @f;", ("@f", f));
        var seguro = await ConsultaComoAsync(s.Principal,
            "EXEC dbo.usp_BuscarClienteSeguro @Nombre = @f;", ("@f", f));
        return Results.Ok(new { filtro = f, vulnerable, seguro });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

// El diagnóstico de la base no se publica: expone el login de conexión y la versión del motor.
app.MapGet("/api/salud", async (HttpContext ctx) =>
{
    var s = await SesionDeAsync(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var f = await ConsultaAsync("SELECT DB_NAME() AS base, SUSER_SNAME() AS conexion, @@VERSION AS motor;");
    return Results.Ok(f[0]);
});

// En pruebas se usa TestServer; fuera, Kestrel escucha HTTP 5080 y HTTPS 5443.
app.Run();

record LoginDto(string? Usuario, string? Password);
record PermisoDto(string? Accion, string? Permiso, string? Tabla, string? Principal);
record MascaraDto(string? Tabla, string? Columna, string? Funcion);
record UsuarioAppDto(string Usuario, bool Activo);
record FirmaDto(int ClienteId, decimal Monto, string? Tipo);
record DocDto(int DocId);
record TarjetaDto(int ClienteId, string? Numero, string? Cvv);
record TarjetaIdDto(int TarjetaId);
record ClienteAeDto(string? Ci, string? Nombre, decimal Saldo, string? Tarjeta);
record ClienteDto(string? Nombre, string? Ci, string? Email, string? Telefono, string? Tarjeta, decimal Saldo);
record EmpleadoDto(string? Nombre, string? Ci, string? Cargo, decimal Salario, string? Email);

record Sesion(string Usuario, string Nombre, string Rol, string Principal)
{
    // Último uso (caducidad deslizante) y creación (caducidad absoluta).
    public DateTime UltimoUso { get; set; } = DateTime.UtcNow;
    public DateTime Creada { get; set; } = DateTime.UtcNow;
}

// Necesario para que las pruebas puedan arrancar la aplicación en memoria.
public partial class Program { }

// La cadena de conexión se resuelve al arrancar (user-secrets) y queda disponible
// para las funciones locales estáticas que abren conexiones.
static class Bd
{
    public static string ConnectionString { get; set; } = "";
    public static string ConnectionStringAe { get; set; } = "";
}
