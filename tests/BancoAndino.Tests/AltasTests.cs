using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace BancoAndino.Tests;

/// Camino feliz de las altas: el rol que puede insertar recibe 201 y la fila
/// queda en el motor, comprobada desde otra sesión que sí lee la tabla completa
/// (riesgos, con UNMASK).
public class AltasTests : IClassFixture<Fabrica>
{
    private readonly Fabrica _fabrica;
    private readonly string _admin;

    public AltasTests(Fabrica fabrica)
    {
        _fabrica = fabrica;

        // Limpieza: app_bancoandino no tiene DELETE, así que se intenta con la
        // cuenta de Windows del equipo (sysadmin local). En el CI, que corre en
        // Linux con una base nueva por corrida, no hay autenticación integrada y
        // la limpieza simplemente no se ejecuta.
        var cadena = fabrica.Services.GetRequiredService<IConfiguration>()
            .GetConnectionString("BancoAndino")!;
        var b = new SqlConnectionStringBuilder(cadena);
        _admin = $"Server={b.DataSource};Database={b.InitialCatalog};Integrated Security=True;" +
                 "TrustServerCertificate=True;Encrypt=False";
    }

    private async Task<HttpClient> ClienteConAsync(string usuario, string clave)
    {
        var c = _fabrica.CreateClient();
        var r = await c.PostAsJsonAsync("/api/login", new { usuario, password = clave });
        r.EnsureSuccessStatusCode();
        // La cookie HttpOnly es la única credencial; el cliente de pruebas la
        // conserva entre peticiones, así que no hay token que copiar.
        return c;
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage r)
        => JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;

    private async Task BorrarAsync(string sql, params (string, object)[] ps)
    {
        try
        {
            await using var cn = new SqlConnection(_admin);
            await cn.OpenAsync();
            await using var cmd = new SqlCommand(sql, cn);
            foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v);
            await cmd.ExecuteNonQueryAsync();
        }
        catch (SqlException)
        {
            // Sin credenciales de administrador (CI): esa base es desechable.
        }
    }

    [Fact]
    public async Task Alta_de_cliente_devuelve_201_y_la_fila_queda_en_la_base()
    {
        var ci = $"7{Random.Shared.Next(100000, 999999)}";
        var ana = await ClienteConAsync("ana", "Cajero_Ana_2027#");
        var id = 0;

        try
        {
            var alta = await ana.PostAsJsonAsync("/api/clientes", new
            {
                nombre = "Cliente de prueba (test)",
                ci,
                email = "alta.test@correo.bo",
                telefono = "70000000",
                tarjeta = "4532-0000-0000-0000",
                saldo = 321.50m
            });

            Assert.Equal(HttpStatusCode.Created, alta.StatusCode);
            id = (await JsonAsync(alta)).GetProperty("clienteId").GetInt32();

            // Otra sesión, otro principal: si la fila se ve, está persistida.
            var maria = await ClienteConAsync("maria", "Riesgos_Maria_2027#");
            var filas = (await JsonAsync(await maria.GetAsync("/api/datos/clientes"))).GetProperty("filas");
            var fila = filas.EnumerateArray().SingleOrDefault(f => f.GetProperty("ClienteID").GetInt32() == id);

            Assert.NotEqual(JsonValueKind.Undefined, fila.ValueKind);
            Assert.Equal("Cliente de prueba (test)", fila.GetProperty("Nombre").GetString());
            Assert.Equal(ci, fila.GetProperty("CI").GetString()!.Trim());
            Assert.Equal(321.50m, fila.GetProperty("SaldoCuenta").GetDecimal());
        }
        finally
        {
            if (id > 0)
                await BorrarAsync("DELETE FROM dbo.Clientes WHERE ClienteID = @id;", ("@id", id));
        }
    }

    [Fact]
    public async Task Alta_de_empleado_devuelve_201_y_la_fila_queda_en_la_base()
    {
        var ci = $"8{Random.Shared.Next(100000, 999999)}";
        var luis = await ClienteConAsync("luis", "Super_Luis_2027#");
        var id = 0;

        try
        {
            var alta = await luis.PostAsJsonAsync("/api/empleados", new
            {
                nombre = "Empleado de prueba (test)",
                ci,
                cargo = "Cajero",
                salario = 4800m,
                email = "empleado.test@bancoandino.bo"
            });

            Assert.Equal(HttpStatusCode.Created, alta.StatusCode);
            id = (await JsonAsync(alta)).GetProperty("empleadoId").GetInt32();

            var maria = await ClienteConAsync("maria", "Riesgos_Maria_2027#");
            var filas = (await JsonAsync(await maria.GetAsync("/api/datos/empleados"))).GetProperty("filas");
            var fila = filas.EnumerateArray().SingleOrDefault(f => f.GetProperty("EmpleadoID").GetInt32() == id);

            Assert.NotEqual(JsonValueKind.Undefined, fila.ValueKind);
            Assert.Equal("Empleado de prueba (test)", fila.GetProperty("Nombre").GetString());
            Assert.Equal(ci, fila.GetProperty("CI").GetString()!.Trim());
            Assert.Equal(4800m, fila.GetProperty("Salario").GetDecimal());
        }
        finally
        {
            if (id > 0)
                await BorrarAsync("DELETE FROM dbo.Empleados WHERE EmpleadoID = @id;", ("@id", id));
        }
    }
}
