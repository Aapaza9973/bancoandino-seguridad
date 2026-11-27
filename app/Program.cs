using System.Collections.Concurrent;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddUserSecrets<Program>(optional: true);
var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

Bd.ConnectionString = builder.Configuration.GetConnectionString("BancoAndino")
    ?? throw new InvalidOperationException(
        "Falta la cadena de conexión 'BancoAndino'. Configúrala con: " +
        "dotnet user-secrets set \"ConnectionStrings:BancoAndino\" \"Server=...\"");

var sesiones = new ConcurrentDictionary<string, Sesion>();

// Política de autenticación: 5 fallos bloquean la cuenta 5 minutos y la sesión
// caduca a los 30 minutos sin uso (caducidad deslizante).
const int MaxIntentosFallidos = 5;
var minutosBloqueo = 5;
var vidaSesion = TimeSpan.FromMinutes(30);

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
static async Task<List<Dictionary<string, object?>>> ConsultaComoAsync(string principal, string sql)
{
    await using var cn = new SqlConnection(Bd.ConnectionString);
    await cn.OpenAsync();
    try
    {
        await using var cmd = new SqlCommand($"EXECUTE AS USER = @__usr;\n{sql}\nREVERT;", cn);
        cmd.Parameters.AddWithValue("@__usr", principal);
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
    return h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? h[7..].Trim() : null;
}

Sesion? SesionDe(HttpContext ctx)
{
    var t = Token(ctx);
    if (t is null || !sesiones.TryGetValue(t, out var s)) return null;

    if (DateTime.UtcNow - s.UltimoUso > vidaSesion)
    {
        sesiones.TryRemove(t, out _);
        return null;
    }

    s.UltimoUso = DateTime.UtcNow;
    return s;
}

// ---------- autenticación ----------
app.MapPost("/api/login", async (LoginDto dto) =>
{
    if (string.IsNullOrWhiteSpace(dto.Usuario) || string.IsNullOrEmpty(dto.Password))
        return Results.BadRequest(new { error = "Usuario y contraseña son obligatorios." });

    var usuario = dto.Usuario.Trim();

    // 1) ¿La cuenta está bloqueada por intentos fallidos previos?
    var estado = await ConsultaAsync(
        @"SELECT Activo,
                 ISNULL(DATEDIFF(SECOND, SYSUTCDATETIME(), BloqueadoHasta), 0) AS segundos_bloqueo
          FROM dbo.UsuariosApp WHERE Usuario = @u",
        ("@u", usuario));

    if (estado.Count > 0 && Convert.ToInt32(estado[0]["segundos_bloqueo"]) > 0)
    {
        var minutos = (Convert.ToInt32(estado[0]["segundos_bloqueo"]) + 59) / 60;
        return Results.Json(new
        {
            error = $"Cuenta bloqueada por intentos fallidos. Reintenta en {minutos} minuto(s).",
            bloqueado = true
        }, statusCode: 423);
    }

    // 2) Comparación del hash: la clave nunca se guarda ni se consulta en claro.
    var filas = await ConsultaAsync(
        @"SELECT Usuario, NombreCompleto, PrincipalBD, Rol
          FROM dbo.UsuariosApp
          WHERE Usuario = @u AND Activo = 1
            AND Hash = HASHBYTES('SHA2_256', Sal + @p)",
        ("@u", usuario), ("@p", dto.Password));

    if (filas.Count == 0)
    {
        // Solo se cuentan los fallos de cuentas existentes: no se revela si el usuario existe.
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

    var f = filas[0];
    var sesion = new Sesion(
        (string)f["Usuario"]!, (string)f["NombreCompleto"]!,
        (string)f["Rol"]!, (string)f["PrincipalBD"]!);
    // Login correcto: se limpia el contador de fallos y se abre la sesión.
    await EjecutarAsync(
        "UPDATE dbo.UsuariosApp SET IntentosFallidos = 0, BloqueadoHasta = NULL WHERE Usuario = @u;",
        ("@u", sesion.Usuario));

    var token = Guid.NewGuid().ToString("N");
    sesiones[token] = sesion;

    return Results.Ok(new
    {
        token, usuario = sesion.Usuario, nombre = sesion.Nombre,
        rol = sesion.Rol, principal = sesion.Principal,
        expira_minutos = (int)vidaSesion.TotalMinutes
    });
});

app.MapPost("/api/logout", (HttpContext ctx) =>
{
    var t = Token(ctx);
    if (t is not null) sesiones.TryRemove(t, out _);
    return Results.Ok(new { ok = true });
});

app.MapGet("/api/sesion", async (HttpContext ctx) =>
{
    var s = SesionDe(ctx);
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
    var s = SesionDe(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (!tablas.TryGetValue(tabla, out var nombre))
        return Results.NotFound(new { error = "Tabla no válida." });

    try
    {
        var filas = await ConsultaComoAsync(s.Principal, $"SELECT TOP 100 * FROM {nombre};");
        return Results.Ok(new { tabla = nombre, principal = s.Principal, filas });
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
    var s = SesionDe(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol is not ("dba" or "auditor"))
        return Results.Json(new { error = "Solo auditoría y administración pueden ver el registro." }, statusCode: 403);

    var filas = await ConsultaAsync(
        @"SELECT TOP 200 event_time, server_principal_name, database_principal_name,
                 object_name, action_id, succeeded, statement
          FROM sys.fn_get_audit_file('C:\AuditLogs\BancoAndino\*', DEFAULT, DEFAULT)
          ORDER BY event_time DESC;");
    return Results.Ok(new { filas });
});

// ---------- administración (solo dba) ----------
app.MapGet("/api/admin/estado", async (HttpContext ctx) =>
{
    var s = SesionDe(ctx);
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
                 ISNULL(OBJECT_NAME(p.major_id),'(base de datos)') AS objeto
          FROM sys.database_permissions p
          JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
          WHERE dp.type IN ('S','R') AND dp.is_fixed_role = 0 AND dp.name <> 'dbo'
            AND p.class = 1 AND OBJECTPROPERTY(p.major_id,'IsUserTable') = 1
          ORDER BY dp.name, p.permission_name;");

    var appUsuarios = await ConsultaAsync(
        "SELECT Usuario, NombreCompleto, PrincipalBD, Rol, Activo FROM dbo.UsuariosApp ORDER BY Rol, Usuario;");

    return Results.Ok(new { mascaras, usuarios, permisos, appUsuarios });
});

app.MapPost("/api/admin/permiso", async (PermisoDto dto, HttpContext ctx) =>
{
    var s = SesionDe(ctx);
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

    var sql = $"{dto.Accion!.ToUpperInvariant()} {dto.Permiso!.ToUpperInvariant()} ON {tabla} TO [{dto.Principal}];";
    try
    {
        await EjecutarAsync(sql);
        return Results.Ok(new { ok = true, ejecutado = sql });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/admin/mascara", async (MascaraDto dto, HttpContext ctx) =>
{
    var s = SesionDe(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    var tabla = dto.Tabla ?? "";
    if (!columnas.TryGetValue(tabla, out var cols) || !cols.Contains(dto.Columna ?? ""))
        return Results.BadRequest(new { error = "Tabla o columna no válida." });

    string sql;
    if (string.IsNullOrEmpty(dto.Funcion))
        sql = $"ALTER TABLE dbo.{tabla} ALTER COLUMN {dto.Columna} DROP MASKED;";
    else if (funciones.Contains(dto.Funcion))
        sql = $"ALTER TABLE dbo.{tabla} ALTER COLUMN {dto.Columna} ADD MASKED WITH (FUNCTION = '{dto.Funcion}');";
    else
        return Results.BadRequest(new { error = "Función de enmascaramiento no válida." });

    try
    {
        await EjecutarAsync(sql);
        return Results.Ok(new { ok = true, ejecutado = sql });
    }
    catch (SqlException ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/admin/usuario", async (UsuarioAppDto dto, HttpContext ctx) =>
{
    var s = SesionDe(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Requiere rol de administración." }, statusCode: 403);

    await EjecutarAsync("UPDATE dbo.UsuariosApp SET Activo = @a WHERE Usuario = @u;",
        ("@a", dto.Activo), ("@u", dto.Usuario));
    return Results.Ok(new { ok = true });
});

// ---------- cifrado en reposo (TDE) ----------
app.MapGet("/api/cifrado", async (HttpContext ctx) =>
{
    var s = SesionDe(ctx);
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
    var s = SesionDe(ctx);
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
    var s = SesionDe(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);

    var filas = await ConsultaAsync(
        @"SELECT DocID, Referencia, ClienteID, Monto, Tipo,
                 CONVERT(varchar(19), FechaFirma, 120) AS fecha_firma,
                 FirmadoPor, FirmaValida, Integridad
          FROM dbo.vw_EstadoFirmas ORDER BY DocID DESC;");
    return Results.Ok(new { filas, rol = s.Rol });
});

app.MapPost("/api/firma/firmar", async (FirmaDto dto, HttpContext ctx) =>
{
    var s = SesionDe(ctx);
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
    var s = SesionDe(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Solo administración puede alterar un documento (demostración)." }, statusCode: 403);

    await EjecutarAsync("EXEC dbo.usp_AlterarTransaccion @id;", ("@id", dto.DocId));
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/firma/restaurar", async (DocDto dto, HttpContext ctx) =>
{
    var s = SesionDe(ctx);
    if (s is null) return Results.Json(new { error = "No autenticado." }, statusCode: 401);
    if (s.Rol != "dba") return Results.Json(new { error = "Solo administración puede restaurar (demostración)." }, statusCode: 403);

    await EjecutarAsync("EXEC dbo.usp_RestaurarTransaccion @id;", ("@id", dto.DocId));
    return Results.Ok(new { ok = true });
});

// ---------- cifrado por columna (tarjeta y CVV) ----------
app.MapGet("/api/columnas", async (HttpContext ctx) =>
{
    var s = SesionDe(ctx);
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
    var s = SesionDe(ctx);
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
    var s = SesionDe(ctx);
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
        // El motor negó abrir la clave. Si es administración, se muestra además el valor real como dbo.
        if (s.Rol != "dba")
            return Results.Json(new { denegado = true, principal = s.Principal, error = ex.Message, numero = (string?)null }, statusCode: 403);

        var filas = await ConsultaAsync($"EXEC dbo.usp_DescifrarTarjeta {dto.TarjetaId};");
        var f = filas.Count > 0 ? filas[0] : null;
        return Results.Ok(new
        {
            ok = true,
            como = "dba",
            principal = s.Principal,
            numero = f?["Numero"],
            cvv = f?["CVV"],
            aviso = ex.Message
        });
    }
});

app.MapGet("/api/salud", async () =>
{
    var f = await ConsultaAsync("SELECT DB_NAME() AS base, SUSER_SNAME() AS conexion, @@VERSION AS motor;");
    return Results.Ok(f[0]);
});

// En pruebas se usa TestServer (sin puerto); fuera de ellas escucha en 5080.
if (app.Environment.IsEnvironment("Testing"))
    app.Run();
else
    app.Run("http://127.0.0.1:5080");

record LoginDto(string? Usuario, string? Password);
record PermisoDto(string? Accion, string? Permiso, string? Tabla, string? Principal);
record MascaraDto(string? Tabla, string? Columna, string? Funcion);
record UsuarioAppDto(string Usuario, bool Activo);
record FirmaDto(int ClienteId, decimal Monto, string? Tipo);
record DocDto(int DocId);
record TarjetaDto(int ClienteId, string? Numero, string? Cvv);
record TarjetaIdDto(int TarjetaId);

record Sesion(string Usuario, string Nombre, string Rol, string Principal)
{
    // Último uso de la sesión: base de la caducidad deslizante.
    public DateTime UltimoUso { get; set; } = DateTime.UtcNow;
}

// Necesario para que las pruebas puedan arrancar la aplicación en memoria.
public partial class Program { }

// La cadena de conexión se resuelve al arrancar (user-secrets) y queda disponible
// para las funciones locales estáticas que abren conexiones.
static class Bd
{
    public static string ConnectionString { get; set; } = "";
}
