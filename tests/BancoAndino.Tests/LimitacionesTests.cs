using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

// La base es compartida por todas las pruebas: se ejecutan una por vez para que
// una revocación global de sesiones no interfiera con otra prueba en curso.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace BancoAndino.Tests;

/// <summary>
/// Pruebas de las limitaciones que quedaron documentadas como deuda:
/// sesiones en memoria, B5 sin metadatos, Always Encrypted sin implementar
/// y el certificado XMLDSig sin cadena de confianza.
/// </summary>
public class LimitacionesTests : IClassFixture<Fabrica>
{
    private readonly Fabrica _fabrica;

    public LimitacionesTests(Fabrica fabrica)
    {
        _fabrica = fabrica;
        var cadena = fabrica.Services.GetRequiredService<IConfiguration>()
            .GetConnectionString("BancoAndino")!;
        using var cn = new SqlConnection(cadena);
        cn.Open();
        using var cmd = new SqlCommand(
            "UPDATE dbo.UsuariosApp SET IntentosFallidos = 0, BloqueadoHasta = NULL;", cn);
        cmd.ExecuteNonQuery();
    }

    private string Cadena()
        => _fabrica.Services.GetRequiredService<IConfiguration>()
            .GetConnectionString("BancoAndino")!;

    private async Task<object?> EscalarAsync(string sql)
    {
        await using var cn = new SqlConnection(Cadena());
        await cn.OpenAsync();
        await using var cmd = new SqlCommand(sql, cn);
        return await cmd.ExecuteScalarAsync();
    }

    private static async Task<HttpClient> ClienteConAsync(Fabrica fabrica, string usuario, string clave)
    {
        var c = fabrica.CreateClient();
        var r = await c.PostAsJsonAsync("/api/login", new { usuario, password = clave });
        r.EnsureSuccessStatusCode();
        // La sesión va en la cookie HttpOnly: el cliente la conserva sola.
        return c;
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage r)
        => JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;

    // ---------- sesiones persistentes ----------

    [Fact]
    public async Task La_sesion_sobrevive_a_otro_proceso_de_la_aplicacion()
    {
        // Primer proceso: abre sesión y se descarta por completo.
        string token;
        using (var primero = new Fabrica())
        {
            var c = primero.CreateClient();
            var login = await c.PostAsJsonAsync("/api/login",
                new { usuario = "ana", password = "Cajero_Ana_2027#" });
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            // El token solo viaja en la cookie HttpOnly: se lee de Set-Cookie.
            token = login.Headers.GetValues("Set-Cookie").First()
                .Split(';')[0]["ba_sesion=".Length..];
        }

        // Segundo proceso, misma cookie: la sesión vive en dbo.SesionesApp.
        using var segundo = new Fabrica();
        var otro = segundo.CreateClient();
        otro.DefaultRequestHeaders.Add("Cookie", $"ba_sesion={token}");
        var sesion = await otro.GetAsync("/api/sesion");

        Assert.Equal(HttpStatusCode.OK, sesion.StatusCode);
        Assert.Equal("cajero_ana", (await JsonAsync(sesion)).GetProperty("principal").GetString());

        // En la tabla no está el token, solo su SHA-256: validar con el token
        // crudo no encuentra la sesión, con su huella sí (lo hace la app).
        await using (var cn = new SqlConnection(Cadena()))
        {
            await cn.OpenAsync();
            await using var cmd = new SqlCommand("EXEC dbo.usp_SesionValidar @TokenHash;", cn);
            cmd.Parameters.AddWithValue("@TokenHash", token);
            await using var rd = await cmd.ExecuteReaderAsync();
            Assert.False(await rd.ReadAsync());
        }
    }

    [Fact]
    public async Task La_revocacion_global_alcanza_a_otras_sesiones_y_procesos()
    {
        var ana = await ClienteConAsync(_fabrica, "ana", "Cajero_Ana_2027#");
        var admin = await ClienteConAsync(_fabrica, "admin", "Dba_Admin_2027#");

        var revocar = await admin.PostAsync("/api/admin/revocar-sesiones", null);
        Assert.Equal(HttpStatusCode.OK, revocar.StatusCode);
        Assert.True((await JsonAsync(revocar)).GetProperty("revocadas").GetInt32() >= 2);

        // La sesión de ana, emitida por otro login, queda cerrada.
        var despues = await ana.GetAsync("/api/sesion");
        Assert.Equal(HttpStatusCode.Unauthorized, despues.StatusCode);
    }

    // ---------- B5: metadatos y ACL para el auditor ----------

    [Fact]
    public async Task El_auditor_lee_la_acl_y_las_mascaras_sin_poder_cambiarlas()
    {
        var sofia = await ClienteConAsync(_fabrica, "sofia", "Auditoria_Sofia_2027#");
        var r = await sofia.GetAsync("/api/metadatos");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var d = await JsonAsync(r);
        Assert.True(d.GetProperty("view_definition").GetBoolean());
        Assert.False(d.GetProperty("control").GetBoolean());
        Assert.True(d.GetProperty("mascaras").GetArrayLength() > 0);
        Assert.True(d.GetProperty("permisos").GetArrayLength() > 0);
        Assert.Contains(d.GetProperty("columnas").EnumerateArray(),
            c => c.GetProperty("tabla").GetString() == "Clientes");

        // El cajero no ve metadatos del modelo.
        var ana = await ClienteConAsync(_fabrica, "ana", "Cajero_Ana_2027#");
        Assert.Equal(HttpStatusCode.Forbidden, (await ana.GetAsync("/api/metadatos")).StatusCode);
    }

    // ---------- Always Encrypted ----------

    [Fact]
    public async Task Always_encrypted_guarda_binario_y_descifra_solo_en_el_cliente()
    {
        var hayClaves = Convert.ToInt32(
            await EscalarAsync("SELECT COUNT(*) FROM sys.column_encryption_keys WHERE name = 'CEK_BancoAndino';")) > 0;

        var maria = await ClienteConAsync(_fabrica, "maria", "Riesgos_Maria_2027#");

        if (!hayClaves)
        {
            // Sin almacén de certificados (por ejemplo en Linux) el endpoint
            // informa el estado en vez de fallar: la prueba verifica eso.
            var estado = await maria.GetAsync("/api/ae/estado");
            Assert.Equal(HttpStatusCode.OK, estado.StatusCode);
            Assert.False((await JsonAsync(estado)).GetProperty("disponible").GetBoolean());
            return;
        }

        var ci = Random.Shared.Next(1_000_000, 9_999_999).ToString();
        var alta = await maria.PostAsJsonAsync("/api/ae/guardar", new
        {
            ci,
            nombre = "Cliente Always Encrypted",
            saldo = 1234.56m,
            tarjeta = "4000-0000-0000-1234"
        });
        Assert.Equal(HttpStatusCode.OK, alta.StatusCode);
        Assert.True((await JsonAsync(alta)).GetProperty("clienteId").GetInt32() > 0);

        // Búsqueda por igualdad: solo posible porque CI es determinista.
        var buscar = await maria.GetAsync($"/api/ae/buscar?ci={ci}");
        Assert.Equal(HttpStatusCode.OK, buscar.StatusCode);
        var filas = (await JsonAsync(buscar)).GetProperty("filas");
        Assert.Equal(1, filas.GetArrayLength());
        Assert.Equal("Cliente Always Encrypted", filas[0].GetProperty("Nombre").GetString());
        Assert.Equal(1234.56m, filas[0].GetProperty("SaldoCuenta").GetDecimal());

        // El mismo SELECT sin descifrado en el cliente devuelve base64, no texto.
        var estadoAe = await JsonAsync(await maria.GetAsync("/api/ae/estado"));
        Assert.True(estadoAe.GetProperty("disponible").GetBoolean());
        var cifrada = estadoAe.GetProperty("cifrada")[0];
        Assert.NotEqual("Cliente Always Encrypted", cifrada.GetProperty("Nombre").GetString());
        Assert.True(cifrada.GetProperty("Nombre").GetString()!.Length > 40);
        // La misma consulta con cifrado activo sí devuelve texto claro.
        var descifrada = estadoAe.GetProperty("descifrada");
        Assert.True(descifrada.GetArrayLength() > 0);
        Assert.Equal("Ana Quispe", descifrada[0].GetProperty("Nombre").GetString());

        // El auditor no tiene SELECT sobre la tabla cifrada.
        var sofia = await ClienteConAsync(_fabrica, "sofia", "Auditoria_Sofia_2027#");
        Assert.Equal(HttpStatusCode.Forbidden, (await sofia.GetAsync("/api/ae/clientes")).StatusCode);

        // El motor tampoco entrega texto claro a quien consulta directo, ni
        // siquiera al usuario con SELECT: sin la CMK solo hay binario.
        await using var cn = new SqlConnection(Cadena());
        await cn.OpenAsync();
        await using (var imp = new SqlCommand("EXECUTE AS USER = 'riesgos_maria';", cn))
            await imp.ExecuteNonQueryAsync();
        try
        {
            await using var cmd = new SqlCommand("SELECT TOP 1 CI FROM dbo.ClientesAE;", cn);
            await using var rd = await cmd.ExecuteReaderAsync();
            Assert.True(await rd.ReadAsync());
            Assert.IsType<byte[]>(rd.GetValue(0));
        }
        finally
        {
            await using var revert = new SqlCommand("REVERT;", cn);
            await revert.ExecuteNonQueryAsync();
        }
    }

    // ---------- XMLDSig con cadena de CA ----------

    [Fact]
    public async Task La_firma_xmldsig_se_valida_contra_la_raiz_de_la_CA()
    {
        var admin = await ClienteConAsync(_fabrica, "admin", "Dba_Admin_2027#");
        var r = await admin.GetAsync("/api/firma/xmldsig");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var d = await JsonAsync(r);
        Assert.True(d.GetProperty("valida").GetBoolean());

        var hayPfx = BuscarArchivo("pki/firma-bancoandino.pfx") is not null;
        if (hayPfx)
        {
            Assert.True(d.GetProperty("cadena_valida").GetBoolean());
            Assert.Contains("BancoAndino Root CA", d.GetProperty("emisor").GetString());
            Assert.Contains("BancoAndino Root CA", d.GetProperty("raiz").GetString());
        }
        else
        {
            Assert.False(d.GetProperty("cadena_valida").GetBoolean());
            Assert.Contains("efímero", d.GetProperty("origen").GetString());
        }
    }

    private static string? BuscarArchivo(string relativo)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            var candidato = Path.Combine(dir.FullName, relativo.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidato)) return candidato;
        }
        return null;
    }
}
