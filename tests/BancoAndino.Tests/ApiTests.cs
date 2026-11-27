using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
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

    public ApiTests(Fabrica fabrica) => _fabrica = fabrica;

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
}
