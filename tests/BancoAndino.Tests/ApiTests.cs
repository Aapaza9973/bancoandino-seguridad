using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace BancoAndino.Tests;

/// Arranca la aplicación en memoria (TestServer) con el entorno "Testing".
public sealed class Fabrica : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
        => builder.UseEnvironment("Testing");
}

public class ApiTests : IClassFixture<Fabrica>
{
    private readonly Fabrica _fabrica;

    public ApiTests(Fabrica fabrica)
    {
        _fabrica = fabrica;
        // Las pruebas comparten base: se parte sin bloqueos de una corrida anterior.
        var cadena = fabrica.Services.GetRequiredService<IConfiguration>()
            .GetConnectionString("BancoAndino")!;
        using var cn = new SqlConnection(cadena);
        cn.Open();
        using var cmd = new SqlCommand(
            "UPDATE dbo.UsuariosApp SET IntentosFallidos = 0, BloqueadoHasta = NULL;", cn);
        cmd.ExecuteNonQuery();
    }

    private static async Task<HttpClient> ClienteConAsync(Fabrica fabrica, string usuario, string clave)
    {
        var c = fabrica.CreateClient();
        var r = await c.PostAsJsonAsync("/api/login", new { usuario, password = clave });
        r.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await r.Content.ReadAsStringAsync());
        c.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", doc.RootElement.GetProperty("token").GetString());
        return c;
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage r)
        => JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;

    [Fact]
    public async Task Login_con_clave_incorrecta_devuelve_401()
    {
        var c = _fabrica.CreateClient();
        var r = await c.PostAsJsonAsync("/api/login", new { usuario = "ana", password = "no-es-la-clave" });

        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task Recurso_protegido_sin_token_devuelve_401()
    {
        var c = _fabrica.CreateClient();
        var r = await c.GetAsync("/api/sesion");

        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task Salud_exige_token_y_responde_con_sesion()
    {
        var anonimo = _fabrica.CreateClient();
        var sinToken = await anonimo.GetAsync("/api/salud");
        Assert.Equal(HttpStatusCode.Unauthorized, sinToken.StatusCode);

        // Con sesión sigue sirviendo de diagnóstico.
        var c = await ClienteConAsync(_fabrica, "ana", "Cajero_Ana_2027#");
        var conToken = await c.GetAsync("/api/salud");
        Assert.Equal(HttpStatusCode.OK, conToken.StatusCode);
        Assert.False(string.IsNullOrWhiteSpace((await JsonAsync(conToken)).GetProperty("motor").GetString()));
    }

    [Fact]
    public async Task Cajero_ve_los_datos_pero_no_puede_descifrar_la_tarjeta()
    {
        var c = await ClienteConAsync(_fabrica, "ana", "Cajero_Ana_2027#");

        // La tabla se puede leer (los últimos 4 son de referencia)...
        var lista = await c.GetAsync("/api/columnas");
        Assert.Equal(HttpStatusCode.OK, lista.StatusCode);

        // ...pero el motor niega abrir la clave simétrica.
        var descifrar = await c.PostAsJsonAsync("/api/columnas/descifrar", new { tarjetaId = 1 });
        Assert.Equal(HttpStatusCode.Forbidden, descifrar.StatusCode);

        var cuerpo = await JsonAsync(descifrar);
        Assert.True(cuerpo.GetProperty("denegado").GetBoolean());
        Assert.Equal(JsonValueKind.Null, cuerpo.GetProperty("numero").ValueKind);
    }

    [Fact]
    public async Task Riesgos_puede_descifrar_la_tarjeta()
    {
        var c = await ClienteConAsync(_fabrica, "maria", "Riesgos_Maria_2027#");
        var r = await c.PostAsJsonAsync("/api/columnas/descifrar", new { tarjetaId = 1 });

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var cuerpo = await JsonAsync(r);
        var numero = cuerpo.GetProperty("numero").GetString();
        Assert.False(string.IsNullOrWhiteSpace(numero));
        Assert.True(numero!.Length >= 15);
    }

    [Fact]
    public async Task La_base_esta_cifrada_con_TDE()
    {
        var c = await ClienteConAsync(_fabrica, "admin", "Dba_Admin_2027#");
        var r = await c.GetAsync("/api/cifrado");

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var cuerpo = await JsonAsync(r);
        Assert.Equal("ENCRYPTED", cuerpo.GetProperty("tde").GetProperty("estado").GetString());
        Assert.True(cuerpo.GetProperty("tde").GetProperty("longitud").GetInt32() >= 128);
    }

    [Fact]
    public async Task Las_transacciones_firmadas_informan_firma_e_integridad()
    {
        var c = await ClienteConAsync(_fabrica, "admin", "Dba_Admin_2027#");
        var r = await c.GetAsync("/api/firma");

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var filas = (await JsonAsync(r)).GetProperty("filas");
        Assert.True(filas.GetArrayLength() > 0);

        foreach (var f in filas.EnumerateArray())
        {
            Assert.Equal(1, f.GetProperty("FirmaValida").GetInt32());
            Assert.Contains(f.GetProperty("Integridad").GetString(), new[] { "INTACTO", "ALTERADO" });
        }
    }

    // ---------- control de fuerza bruta y caducidad de sesión ----------

    private async Task EjecutarSqlAsync(string sql)
    {
        var cadena = _fabrica.Services.GetRequiredService<IConfiguration>()
            .GetConnectionString("BancoAndino")!;
        await using var cn = new SqlConnection(cadena);
        await cn.OpenAsync();
        await using var cmd = new SqlCommand(sql, cn);
        await cmd.ExecuteNonQueryAsync();
    }

    /// Ejecuta como el principal de base y devuelve la excepción del motor, para
    /// comprobar que una columna denegada produce el error 230.
    private async Task<SqlException> EjecutarComoAsync(string principal, string sql)
    {
        var cadena = _fabrica.Services.GetRequiredService<IConfiguration>()
            .GetConnectionString("BancoAndino")!;
        await using var cn = new SqlConnection(cadena);
        await cn.OpenAsync();
        await using var cmd = new SqlCommand($"EXECUTE AS USER = @u;\n{sql}\nREVERT;", cn);
        cmd.Parameters.AddWithValue("@u", principal);
        return await Assert.ThrowsAsync<SqlException>(() => cmd.ExecuteNonQueryAsync());
    }

    [Fact]
    public async Task La_cuenta_se_bloquea_tras_cinco_intentos_fallidos()
    {
        // Estado limpio por si otra corrida dejó el bloqueo activo.
        await EjecutarSqlAsync(
            "UPDATE dbo.UsuariosApp SET IntentosFallidos = 0, BloqueadoHasta = NULL WHERE Usuario = 'luis';");

        var c = _fabrica.CreateClient();
        HttpResponseMessage r = null!;
        for (var i = 0; i < 5; i++)
            r = await c.PostAsJsonAsync("/api/login", new { usuario = "luis", password = "clave-incorrecta" });

        Assert.Equal(HttpStatusCode.Locked, r.StatusCode);

        // Aun con la clave correcta la cuenta sigue bloqueada...
        var conClaveBuena = await c.PostAsJsonAsync("/api/login", new { usuario = "luis", password = "Super_Luis_2027#" });
        Assert.Equal(HttpStatusCode.Locked, conClaveBuena.StatusCode);
        Assert.True((await JsonAsync(conClaveBuena)).GetProperty("bloqueado").GetBoolean());

        // ...y al expirar el bloqueo vuelve a entrar.
        await EjecutarSqlAsync(
            "UPDATE dbo.UsuariosApp SET IntentosFallidos = 0, BloqueadoHasta = NULL WHERE Usuario = 'luis';");
        var despues = await c.PostAsJsonAsync("/api/login", new { usuario = "luis", password = "Super_Luis_2027#" });
        Assert.Equal(HttpStatusCode.OK, despues.StatusCode);
    }

    [Fact]
    public async Task Un_login_correcto_reinicia_el_contador_de_fallos()
    {
        var c = _fabrica.CreateClient();
        for (var i = 0; i < 3; i++)
            await c.PostAsJsonAsync("/api/login", new { usuario = "ana", password = "clave-incorrecta" });

        var ok = await c.PostAsJsonAsync("/api/login", new { usuario = "ana", password = "Cajero_Ana_2027#" });

        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.True((await JsonAsync(ok)).GetProperty("expira_minutos").GetInt32() > 0);
    }

    // ---------- permisos por columna ----------

    [Fact]
    public async Task Cajero_lee_empleados_pero_no_la_columna_salario()
    {
        var c = await ClienteConAsync(_fabrica, "ana", "Cajero_Ana_2027#");
        var r = await c.GetAsync("/api/datos/empleados");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var cuerpo = await JsonAsync(r);
        var nombres = cuerpo.GetProperty("filas")[0].EnumerateObject().Select(p => p.Name).ToList();
        Assert.Contains("Nombre", nombres);
        Assert.Contains("Cargo", nombres);
        Assert.DoesNotContain("Salario", nombres);
        Assert.Contains("Salario",
            cuerpo.GetProperty("columnas_ocultas").EnumerateArray().Select(x => x.GetString()!));

        // La aplicación no filtra: el motor niega la columna.
        var ex = await EjecutarComoAsync("cajero_ana", "SELECT TOP 1 Salario FROM dbo.Empleados;");
        Assert.Equal(230, ex.Number);
    }

    [Fact]
    public async Task Supervisor_no_puede_leer_la_columna_numero_tarjeta()
    {
        var c = await ClienteConAsync(_fabrica, "luis", "Super_Luis_2027#");
        var r = await c.GetAsync("/api/datos/clientes");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var cuerpo = await JsonAsync(r);
        var nombres = cuerpo.GetProperty("filas")[0].EnumerateObject().Select(p => p.Name).ToList();
        Assert.Contains("SaldoCuenta", nombres);
        Assert.DoesNotContain("NumeroTarjeta", nombres);
        Assert.Contains("NumeroTarjeta",
            cuerpo.GetProperty("columnas_ocultas").EnumerateArray().Select(x => x.GetString()!));

        var ex = await EjecutarComoAsync("supervisor_luis", "SELECT TOP 1 NumeroTarjeta FROM dbo.Clientes;");
        Assert.Equal(230, ex.Number);

        // Empleados: el supervisor da de alta y lee, pero el salario sigue
        // denegado por columna (19_altas.sql). Dar de alta clientes, no.
        var empleados = await c.GetAsync("/api/datos/empleados");
        Assert.Equal(HttpStatusCode.OK, empleados.StatusCode);
        var cuerpoEmpleados = await JsonAsync(empleados);
        var columnasEmpleados = cuerpoEmpleados.GetProperty("filas")[0]
            .EnumerateObject().Select(p => p.Name).ToList();
        Assert.DoesNotContain("Salario", columnasEmpleados);
        Assert.Contains("Salario",
            cuerpoEmpleados.GetProperty("columnas_ocultas").EnumerateArray().Select(x => x.GetString()!));
        Assert.True(cuerpoEmpleados.GetProperty("puede_insertar").GetBoolean());

        var exSalario = await EjecutarComoAsync("supervisor_luis", "SELECT TOP 1 Salario FROM dbo.Empleados;");
        Assert.Equal(230, exSalario.Number);

        var altaClientes = await c.PostAsJsonAsync("/api/clientes", new
        {
            nombre = "Cliente de prueba", ci = "1234567", email = "prueba@correo.bo",
            telefono = "70000000", tarjeta = "4532-0000-0000-0000", saldo = 10m
        });
        Assert.Equal(HttpStatusCode.Forbidden, altaClientes.StatusCode);
    }

    // ---------- inferencia, SQLi, auditoría y mínimo privilegio ----------

    [Fact]
    public async Task Inferencia_por_umbral_revela_el_saldo_real()
    {
        var c = await ClienteConAsync(_fabrica, "ana", "Cajero_Ana_2027#");

        var bajo = await c.GetAsync("/api/demo/inferencia?clienteId=1&umbral=15420");
        var alto = await c.GetAsync("/api/demo/inferencia?clienteId=1&umbral=15421");

        Assert.Equal(HttpStatusCode.OK, bajo.StatusCode);
        Assert.Equal(1, (await JsonAsync(bajo)).GetProperty("coincide").GetInt32());
        Assert.Equal(0, (await JsonAsync(alto)).GetProperty("coincide").GetInt32());
    }

    [Fact]
    public async Task La_demo_de_sqli_muestra_la_diferencia()
    {
        var c = await ClienteConAsync(_fabrica, "admin", "Dba_Admin_2027#");
        var filtro = Uri.EscapeDataString("' OR 1=1--");
        var r = await c.GetAsync($"/api/demo/sqli?filtro={filtro}");

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var cuerpo = await JsonAsync(r);
        Assert.True(cuerpo.GetProperty("vulnerable").GetArrayLength() > 0);
        Assert.Equal(0, cuerpo.GetProperty("seguro").GetArrayLength());
    }

    [Fact]
    public async Task La_auditoria_registra_accesos_denegados()
    {
        // El motor deniega la columna y lo deja en el archivo de auditoría.
        var ex = await EjecutarComoAsync("cajero_ana", "SELECT TOP 1 Salario FROM dbo.Empleados;");
        Assert.Equal(230, ex.Number);

        var c = await ClienteConAsync(_fabrica, "sofia", "Auditoria_Sofia_2027#");
        var r = await c.GetAsync("/api/auditoria");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var filas = (await JsonAsync(r)).GetProperty("filas");
        Assert.Contains(filas.EnumerateArray(), f => !f.GetProperty("succeeded").GetBoolean());
    }

    [Fact]
    public async Task La_cuenta_de_aplicacion_no_es_sysadmin_ni_db_owner()
    {
        var cadena = _fabrica.Services.GetRequiredService<IConfiguration>()
            .GetConnectionString("BancoAndino")!;
        await using var cn = new SqlConnection(cadena);
        await cn.OpenAsync();
        await using var cmd = new SqlCommand(
            "SELECT IS_SRVROLEMEMBER('sysadmin') AS sa, IS_ROLEMEMBER('db_owner') AS owner;", cn);
        await using var rd = await cmd.ExecuteReaderAsync();
        Assert.True(await rd.ReadAsync());
        Assert.Equal(0, rd.GetInt32(0));
        Assert.Equal(0, rd.GetInt32(1));
    }

    [Fact]
    public async Task El_dba_no_lee_datos_por_su_cuenta()
    {
        var c = await ClienteConAsync(_fabrica, "admin", "Dba_Admin_2027#");
        var r = await c.GetAsync("/api/datos/clientes");
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact]
    public async Task La_cookie_de_sesion_es_httponly_y_autentica()
    {
        var c = _fabrica.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true });
        var login = await c.PostAsJsonAsync("/api/login", new { usuario = "ana", password = "Cajero_Ana_2027#" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var setCookie = login.Headers.GetValues("Set-Cookie").First();
        Assert.Contains("ba_sesion=", setCookie);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);

        var sesion = await c.GetAsync("/api/sesion");
        Assert.Equal(HttpStatusCode.OK, sesion.StatusCode);
    }

    [Fact]
    public async Task La_firma_xmldsig_es_valida()
    {
        var c = await ClienteConAsync(_fabrica, "admin", "Dba_Admin_2027#");
        var r = await c.GetAsync("/api/firma/xmldsig");

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        var cuerpo = await JsonAsync(r);
        Assert.True(cuerpo.GetProperty("valida").GetBoolean());
        Assert.Contains("<Signature", cuerpo.GetProperty("xml").GetString());
        Assert.Contains("RSA-SHA256", cuerpo.GetProperty("algoritmo").GetString());
    }

    [Fact]
    public async Task El_logout_invalida_el_token()
    {
        var c = await ClienteConAsync(_fabrica, "ana", "Cajero_Ana_2027#");
        var salida = await c.PostAsync("/api/logout", null);
        Assert.Equal(HttpStatusCode.OK, salida.StatusCode);

        var sesion = await c.GetAsync("/api/sesion");
        Assert.Equal(HttpStatusCode.Unauthorized, sesion.StatusCode);
    }
}
