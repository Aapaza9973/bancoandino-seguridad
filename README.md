# Banco Andino · consola de seguridad de base de datos

Proyecto de **Seguridad Informática**: una aplicación ASP.NET Core (net9.0) contra **SQL Server 2022** donde los controles los aplica el motor, no el código. La consola no "simula" permisos: cada consulta viaja como el usuario de base que corresponde (`EXECUTE AS USER`), así que lo que se ve en pantalla es el veredicto real de SQL Server — lo que concede, lo que enmascara y lo que niega.

Sirve para demostrar, sobre una misma base `BancoAndino`: enmascaramiento dinámico (DDM), permisos `GRANT`/`DENY`/`REVOKE`, cifrado en reposo (TDE), cifrado por columna con clave simétrica, firma digital de transacciones con certificado, auditoría a archivo y autenticación de la aplicación con bloqueo por fuerza bruta y sesión deslizante.

## Requisitos

- **SQL Server 2022** (Developer o superior) con autenticación mixta; `sqlcmd` o SSMS.
- **.NET 9 SDK**.
- Carpetas que los scripts y la app esperan:
  - `C:\AuditLogs\BancoAndino\` — destino del server audit (`02_auditoria.sql`).
  - `C:\CertBackup\` — destino del respaldo del certificado TDE (botón de Administración).
- El login de la aplicación necesita `sysadmin` (ver *Deuda conocida*, al final).

## Puesta en marcha

### 0. Base y modelo de seguridad

Ejecutar como `sysadmin` (SSMS, o `sqlcmd -S localhost -E -i archivo.sql`), **en orden** y sobre una instancia limpia:

| Script | Qué crea |
| --- | --- |
| `app/sql/01_esquema.sql` | Base `BancoAndino`, tablas y datos, máscaras DDM, logins/usuarios, roles y permisos (`GRANT`/`DENY`/`UNMASK`). **Borra tablas y logins: no reejecutar con datos.** |
| `app/sql/02_auditoria.sql` | Server audit `Audit_BancoAndino` a archivo y especificación sobre las tablas sensibles. |
| `app/sql/03_usuarios_app.sql` | Tabla `dbo.UsuariosApp`: cuentas de la aplicación con sal + `HASHBYTES`, y el principal de base que cada una suplanta. |
| `app/sql/04_tde.sql` | DMK, certificado del servidor y DEK; enciende TDE y respalda el certificado con su clave privada en `C:\CertBackup\`. |
| `app/sql/05_firma_transacciones.sql` | Certificado `CertTransacciones`, tablas de documentos, `usp_FirmarTransaccion`, `usp_Alterar`/`usp_Restaurar` y la vista `vw_EstadoFirmas`. |
| `app/sql/06_cifrado_columnas.sql` | `CertColumnas` + `SK_Tarjetas` (AES-256), `TarjetasCifradas`, `usp_GuardarTarjeta` y `usp_DescifrarTarjeta`. |
| `app/sql/07_backup_antes_de_actualizar.sql` | Respaldo de SMK, certificado TDE y base antes de cambiar de edición (rutas `C:\BackupBancoAndino\...` fijas: ajustar). |
| `app/sql/08_rotar_password_demo.sql` | Rotación de las claves de demostración (login y hash de la app). |
| `app/sql/09_bloqueo_intentos.sql` | Columnas de control de fuerza bruta en `UsuariosApp` (`IntentosFallidos`, `BloqueadoHasta`, `UltimoIntento`). |

### 1. Cuenta de conexión

La aplicación abre conexiones como una cuenta **sysadmin** y después suplanta al usuario de base con `EXECUTE AS USER`, que es lo que permite mostrar el veredicto del motor. En el equipo de desarrollo usa **autenticación de Windows** (el usuario que administra la instancia); la alternativa es un login SQL dedicado:

```sql
CREATE LOGIN dba_sql WITH PASSWORD = '<clave-fuerte>', CHECK_POLICY = ON;
ALTER SERVER ROLE sysadmin ADD MEMBER dba_sql;
```

### 2. Cadena de conexión en user-secrets

Nunca en el repositorio ni en `appsettings.json`:

```bash
cd app
# Autenticación de Windows (como está configurada en desarrollo)
dotnet user-secrets set "ConnectionStrings:BancoAndino" \
  "Server=localhost;Database=BancoAndino;Integrated Security=True;TrustServerCertificate=True;Encrypt=False"

# O con el login SQL del paso anterior
dotnet user-secrets set "ConnectionStrings:BancoAndino" \
  "Server=localhost;Database=BancoAndino;User Id=dba_sql;Password=<clave-fuerte>;TrustServerCertificate=True;Encrypt=False"
```

`UserSecretsId` del proyecto: `ad7e6ae5-c9a1-4f27-adc4-f3fc4c5fc3d9`.

### 3. Arrancar

```bash
dotnet run --project app
# http://127.0.0.1:5080
```

Interfaz en `app/wwwroot` (HTML/CSS/JS sin compilación). `api.http` trae las peticiones de prueba para la extensión REST Client.

### 4. Cuentas de demostración

| Usuario | Rol de la app | Usuario de base | Qué demuestra |
| --- | --- | --- | --- |
| `ana` | cajero | `cajero_ana` | Ve clientes y transacciones **enmascaradas**; `Empleados` le está **denegado**; no puede descifrar la tarjeta. |
| `luis` | supervisor | `supervisor_luis` | Igual que cajero, sin `DENY` explícito sobre `Empleados`. |
| `maria` | riesgos | `riesgos_maria` | Tiene `UNMASK`: ve los datos reales y **puede descifrar** tarjeta y CVV. |
| `sofia` | auditor | `auditor_sofia` | Lee todo, siempre enmascarado (sin `UNMASK`); no administra nada. |
| `admin` | dba | `dba_admin` | `db_owner`: administra máscaras, permisos, usuarios y el respaldo del certificado. |

Las claves están en `app/sql/08_rotar_password_demo.sql` (son de demostración y viven en el repo; rotarlas antes de cualquier uso real).

## Pruebas

```bash
dotnet test tests/BancoAndino.Tests/BancoAndino.Tests.csproj
```

Levantan la aplicación en memoria (`TestServer`, entorno `Testing`) y **necesitan un SQL Server vivo con los scripts aplicados**: las pruebas consultan la base real para verificar el veredicto del motor (denegación de la clave, TDE encendido, firma válida, bloqueo de cuenta).

En Windows, si la app está corriendo, el `.exe` queda bloqueado y la compilación falla: detenerla antes de probar.

## Integración continua

`.github/workflows/ci-bancoandino.yml` levanta SQL Server 2022 en un contenedor Linux, aplica `01`, `03`, `05`, `06` y los scripts de `app/sql/ci/` (TDE sin respaldo a `C:\`, y un documento firmado de ejemplo), y corre las pruebas con autenticación SQL.

> Estado: el job todavía no completó ninguna corrida — la cuenta de GitHub está bloqueada por facturación. Se resuelve en `github.com/settings/billing`.

## Mapa control → archivo

| Control | Dónde se implementa | Dónde se ve en la consola | Prueba |
| --- | --- | --- | --- |
| Autenticación (sal + SHA-256, sin clave en claro) | `app/sql/03_usuarios_app.sql`, `/api/login` | Pantalla de acceso | `Un_login_correcto_reinicia_el_contador_de_fallos` |
| Bloqueo por fuerza bruta (5 fallos / 5 min) | `app/sql/09_bloqueo_intentos.sql`, `/api/login` | Aviso de cuenta bloqueada | `La_cuenta_se_bloquea_tras_cinco_intentos_fallidos` |
| Sesión deslizante (30 min sin uso) | `Program.cs` → `SesionDe`, `Sesion.UltimoUso` | Chip de usuario | — |
| Enmascaramiento dinámico (DDM) | `01_esquema.sql` §2, `/api/admin/mascara` | Clientes / Empleados / Administración | — |
| Permisos `GRANT` / `DENY` / `REVOKE` | `01_esquema.sql` §4, `/api/admin/permiso`, `ConsultaComoAsync` | Clientes (denegación del motor), Administración | — |
| Cifrado en reposo (TDE) | `04_tde.sql`, `/api/cifrado` | Cifrado (TDE) | `La_base_esta_cifrada_con_TDE` |
| Respaldo del certificado TDE | `04_tde.sql` §5, `/api/cifrado/backup-certificado` (solo `dba`) | Cifrado (TDE) → botón | — |
| Cifrado por columna (AES-256 + `SK_Tarjetas`) | `06_cifrado_columnas.sql`, `/api/columnas*` | Cifrado columnas | `Cajero_ve_los_datos_pero_no_puede_descifrar_la_tarjeta`, `Riesgos_puede_descifrar_la_tarjeta` |
| Firma digital (SHA-256 + RSA) e integridad | `05_firma_transacciones.sql`, `/api/firma*` | Firma digital | `Las_transacciones_firmadas_informan_firma_e_integridad` |
| Auditoría de accesos | `02_auditoria.sql`, `/api/auditoria` | Auditoría (solo auditor y dba) | — |
| Respaldo previo a cambios | `07_backup_antes_de_actualizar.sql` | — | — |
| Autorización de la app por rol | `Program.cs` (`s.Rol`), índice filtrado en `app.js` | Menú lateral | — |

### Endpoints

- `POST /api/login`, `POST /api/logout`, `GET /api/sesion` — sesión y permisos efectivos.
- `GET /api/datos/{clientes|transacciones|empleados}` — lectura suplantando al usuario de base.
- `GET /api/auditoria` — registros del server audit.
- `GET /api/admin/estado`, `POST /api/admin/{permiso|mascara|usuario}` — solo rol `dba`.
- `GET /api/cifrado`, `POST /api/cifrado/backup-certificado`; `GET /api/firma`, `POST /api/firma/{firmar|alterar|restaurar}`; `GET /api/columnas`, `POST /api/columnas/{guardar|descifrar}`.
- `GET /api/salud` — **requiere token**; devuelve base, login de conexión y versión del motor.

## Estructura

```
app/                 API mínima + frontend estático
  Program.cs         endpoints, login, sesiones, suplantación
  wwwroot/           index.html, styles.css, app.js
  sql/               01→09 modelo de seguridad
  sql/ci/            variantes para el contenedor de integración continua
tests/               xUnit contra la app en memoria
.github/workflows/   CI con SQL Server en contenedor
api.http             peticiones manuales
```

## Deuda conocida

1. **La cuenta de conexión es `sysadmin`.** El mínimo privilegio vive en la base (roles, permisos y máscaras), pero la conexión de la app no: si esa cuenta se compromete, el modelo es cosmético. Pendiente: cuenta de aplicación acotada a `EXECUTE AS` + lectura de catálogo.
2. **Atajo de `dba` al descifrar:** cuando el motor niega, `POST /api/columnas/descifrar` reintenta como dueño para mostrar el valor real. Es una demostración y a la vez una puerta trasera del endpoint.
3. **Sin TLS** (`http://127.0.0.1:5080`): publicar detrás de un proxy o con certificado. El token vive en `sessionStorage` y las sesiones en un diccionario en memoria (se pierden al reiniciar, sin revocación global).
4. **Secretos en claro** en `04_tde.sql`, `05_firma_transacciones.sql` y `Program.cs` (clave de la DMK y del respaldo del certificado). Rotarlos y moverlos a user-secrets.
5. **Continuidad:** sin respaldo de la DMK y del certificado TDE, el `.bak` no se restaura en otro servidor. Falta el procedimiento de restauración probado.
