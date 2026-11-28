# Banco Andino · consola de seguridad de base de datos

Proyecto de **Seguridad Informática**: una aplicación ASP.NET Core (net9.0) contra **SQL Server 2022** donde los controles los aplica el motor, no el código. La consola no "simula" permisos: cada consulta viaja como el usuario de base que corresponde (`EXECUTE AS USER`), así que lo que se ve en pantalla es el veredicto real de SQL Server — lo que concede, lo que enmascara y lo que niega.

Sobre una misma base `BancoAndino` demuestra: matriz de protección, mínimo privilegio, permisos por columna, enmascaramiento dinámico (DDM) e inferencia por `WHERE`, SQL injection comparada, auditoría a archivo con accesos denegados, cifrado en reposo (TDE), cifrado por columna, frase de paso, **Always Encrypted con la CMK fuera del motor**, firma digital de transacciones y **XMLDSig con cadena de CA**, contraseñas PBKDF2, TLS, sesión con cookie `HttpOnly` **persistida en la base**, revocación global y restauración verificada **en otra instancia**.

## Requisitos

- **SQL Server 2022** (Developer o superior) con autenticación mixta; `sqlcmd` o SSMS.
- **.NET 9 SDK**.
- **Windows** para Always Encrypted (`MSSQL_CERTIFICATE_STORE`); en Linux/nube se cambia el proveedor por Azure Key Vault.
- **Docker** solo para las verificaciones de restauración en otra instancia y de CI local.
- Carpetas que los scripts y la app esperan:
  - `C:\AuditLogs\BancoAndino\` — destino del server audit (`02_auditoria.sql`; la ruta se puede cambiar con `-v AuditDir=...`).
  - `C:\CertBackup\` — respaldo del certificado TDE desde Administración.
  - `C:\BackupBancoAndino\` — respaldos y restauración de prueba.
- Certificado de desarrollo para HTTPS: `dotnet dev-certs https` (el proyecto escucha HTTPS en `5443`).

## Puesta en marcha

### 0. Base y modelo de seguridad

Ejecutar como `sysadmin` (SSMS, o `sqlcmd -S localhost -E -i archivo.sql`), **en orden**, sobre una instancia limpia:

| Script | Qué crea |
| --- | --- |
| `app/sql/01_esquema.sql` | Base `BancoAndino`, tablas y datos, máscaras DDM, logins/usuarios, roles, permisos por columna, login `app_bancoandino` (sin `sysadmin` ni `db_owner`) y `dba_admin` sin `db_owner`. **Borra tablas y logins: no reejecutar con datos.** |
| `app/sql/02_auditoria.sql` | Server audit `Audit_BancoAndino` a archivo (`QUEUE_DELAY = 0`), logins fallidos/exitosos, SELECT de datos sensibles y grupos de permisos/DDL/roles. Requiere `-v AuditDir='C:\AuditLogs\BancoAndino\'` (en CI, `/var/opt/mssql/audit/`). |
| `app/sql/03_usuarios_app.sql` | `dbo.UsuariosApp` con **PBKDF2-HMAC-SHA256** (sal aleatoria de 16 bytes, 210.000 iteraciones) y el principal de base que cada cuenta suplanta. |
| `app/sql/04_tde.sql` | DMK, certificado del servidor y DEK; enciende TDE, respalda el certificado y da `CONTROL` sobre él a `app_bancoandino`. |
| `app/sql/05_firma_transacciones.sql` | `CertTransacciones`, documentos firmados, `usp_FirmarTransaccion`, alterar/restaurar y `vw_EstadoFirmas`. |
| `app/sql/06_cifrado_columnas.sql` | `CertColumnas` + `SK_Tarjetas` (AES-256), `TarjetasCifradas`, `usp_GuardarTarjeta` y `usp_DescifrarTarjeta`. |
| `app/sql/07_backup_antes_de_actualizar.sql` | Respaldo de SMK, certificado TDE y base con `COMPRESSION, CHECKSUM` y **`ENCRYPTION (AES_256)`**. |
| `app/sql/08_rotar_password_demo.sql` | Rotación de las claves de demostración de la aplicación (hash PBKDF2). |
| `app/sql/09_bloqueo_intentos.sql` | Columnas de control de fuerza bruta (`IntentosFallidos`, `BloqueadoHasta`, `UltimoIntento`). |
| `app/sql/10_demo_sqli.sql` | `usp_BuscarClienteVulnerable` (concatena) y `usp_BuscarClienteSeguro` (parametriza). Solo `dba_admin`. |
| `app/sql/11_comparacion_cifrado.sql` | Tabla y procedimientos con `EncryptByPassPhrase`; prueba de frase correcta/incorrecta. |
| `app/sql/12_restauracion_prueba.sql` | `RESTORE VERIFYONLY`, restauración a `BancoAndino_Restaurada`, `DBCC CHECKDB`, conteos y firmas. |
| `app/sql/13_admin_procs.sql` | `usp_AdminPermiso` y `usp_AdminMascara` con `EXECUTE AS OWNER`: administrar sin dar `CONTROL` a la app. |
| `app/sql/14_auditoria_lector.sql` | `usp_LeerAuditoria`, firmado por `CertAuditoria` (que tiene `CONTROL SERVER`); la app solo recibe `EXECUTE`. Deriva la ruta del audit, sirve en Windows y Linux. |
| `app/sql/15_auditoria_objetos.sql` | Consolida la especificación de auditoría con tarjetas, firmas, usuarios y `EXECUTE` sobre `usp_DescifrarTarjeta`. |
| `app/sql/16_always_encrypted.sql` | `dbo.ClientesAE` con `CI` determinista y nombre/saldo/tarjeta aleatorios, más los permisos. Idempotente: si no hay CEK, avisa y no falla (así corre en el CI de Linux). |
| `app/sql/17_sesiones.sql` | `dbo.SesionesApp` + `usp_SesionCrear/Validar/Cerrar/RevocarTodas`: la sesión deja de vivir en el proceso. |
| `app/sql/18_metadatos.sql` | `VIEW DEFINITION` para `rol_auditor` y verificación en su contexto (cierre de B5). |
| `app/sql/19_altas.sql` | `INSERT` para `rol_cajero` en `Clientes` y para `rol_supervisor` en `Empleados` (con `SELECT` sin `Salario`): el alta de la consola la autoriza el motor. Idempotente. |

### 0.1 Claves del cliente: PKI de firma y Always Encrypted

```bash
# CA raíz + certificado de firma XMLDSig (pki/BancoAndino-RootCA.cer y firma-bancoandino.pfx)
powershell -NoProfile -ExecutionPolicy Bypass -File pki/crear-pki.ps1

# Certificado CMK en CurrentUser\My, con clave privada no exportable
powershell -NoProfile -ExecutionPolicy Bypass -File pki/crear-cmk.ps1

# CEK cifrada con RSA-OAEP, metadatos CMK/CEK en el motor, tabla y 5 filas de ejemplo
dotnet run --project tools/AeSetup

# Permisos de la tabla cifrada (AeSetup ya la crea; este script es idempotente)
sqlcmd -S localhost -d BancoAndino -b -i app/sql/16_always_encrypted.sql
```

`tools/AeSetup` usa `SqlColumnEncryptionCertificateStoreProvider` para cifrar la CEK; la clave privada de la CMK nunca sale del equipo. `pki/*.pfx|*.pvk|*.key` están en `.gitignore`: cada entorno genera los suyos.

### 1. Cuenta de conexión

La aplicación se conecta como **`app_bancoandino`**, que **no es `sysadmin` ni `db_owner`**:

- `IMPERSONATE` sobre `cajero_ana`, `supervisor_luis`, `riesgos_maria`, `auditor_sofia` y `dba_admin`.
- `VIEW DEFINITION`, `VIEW SERVER STATE` y `CONTROL` sobre el certificado TDE de `master`.
- `SELECT, UPDATE` en `UsuariosApp`, `SELECT` en catálogo y `EXECUTE` solo en los procedimientos que necesita (firma, tarjetas, administración, auditoría, sesiones).

`dba_admin` tampoco es `db_owner`: administra permisos y máscaras a través de `usp_AdminPermiso`/`usp_AdminMascara` y no puede leer las tablas de negocio. La justificación está en `MATRIZ-DE-PROTECCION.md`.

### 2. Cadena de conexión en user-secrets

Nunca en el repositorio ni en `appsettings.json`:

```bash
cd app
dotnet user-secrets set "ConnectionStrings:BancoAndino" \
  "Server=localhost;Database=BancoAndino;User Id=app_bancoandino;Password=Apl1cacion.Andino#27;TrustServerCertificate=True;Encrypt=False"
```

La app deriva de esa cadena una segunda con **`Column Encryption Setting=Enabled`** para las columnas de Always Encrypted; no hay que añadirlo a mano (si se añadiera, se perdería la comparación “con/sin descifrado”).

`UserSecretsId` del proyecto: `ad7e6ae5-c9a1-4f27-adc4-f3fc4c5fc3d9`.

### 3. Arrancar

```bash
dotnet run --project app
# HTTP  http://127.0.0.1:5080   (preview local)
# HTTPS https://127.0.0.1:5443  (certificado de desarrollo)
```

La sesión usa la cookie **`ba_sesion`** (`HttpOnly`, `SameSite=Strict`, `Secure` en HTTPS) además del `Bearer` de la API:

- el token se guarda **hasheado (SHA-256) en `dbo.SesionesApp`**, así que un reinicio del proceso o un segundo nodo no cierran la sesión;
- caducidad deslizante de **30 minutos** y absoluta de **8 horas**, evaluadas por el motor en el `WHERE` de `usp_SesionValidar` (una sola escritura y sin barrido de tabla por request); las filas vencidas o revocadas se borran en el login (`usp_SesionCrear`) con un índice filtrado sobre `UltimoUso` (`WHERE Revocada = 0`), que convierte la limpieza en una búsqueda de rango y no en un recorrido de la tabla; la caducidad absoluta no lleva índice ni barrido propio porque una sesión vencida deja de renovarse y ese mismo barrido la alcanza dentro de los 30 minutos siguientes;
- `POST /api/admin/revocar-sesiones` marca todas las sesiones como revocadas en la tabla (solo `dba`);
- las mutaciones con `Origin` de otro host se rechazan con `403` (CSRF).

Interfaz en `app/wwwroot` (HTML/CSS/JS sin compilación). `api.http` trae peticiones de prueba.

### 4. Cuentas de demostración

| Usuario | Rol de la app | Usuario de base | Qué demuestra |
| --- | --- | --- | --- |
| `ana` | cajero | `cajero_ana` | Clientes y transacciones **enmascaradas**; de `Empleados` solo columnas permitidas (**sin `Salario`**, error 230); no descifra la tarjeta; opera Always Encrypted. |
| `luis` | supervisor | `supervisor_luis` | El motor le **niega la columna `NumeroTarjeta`**; tampoco lee `Empleados` ni la tabla cifrada. |
| `maria` | riesgos | `riesgos_maria` | Tiene `UNMASK`: ve los datos reales, **descifra** tarjeta y CVV y opera Always Encrypted. |
| `sofia` | auditor | `auditor_sofia` | Lee auditoría, **metadatos y ACL** (B5); no administra ni descifra. |
| `admin` | dba | `dba_admin` | Administra permisos, máscaras, usuarios, sesiones y el certificado TDE; **no lee las tablas de negocio**. |

Claves de la aplicación: `ana/Cajero_Ana_2027#`, `luis/Super_Luis_2027#`, `maria/Riesgos_Maria_2027#`, `sofia/Auditoria_Sofia_2027#`, `admin/Dba_Admin_2027#`. Son PBKDF2 en `UsuariosApp`, independientes de la clave del login de base. Los logins de SQL Server usan claves distintas (`Caj3ro.Andino#27`, `Sup3rvisor.Andino#27`, `Ri3sgos.Andino#27`, `Aud1tor.Andino#27`, `Adm1n.Andino#27`, `Apl1cacion.Andino#27`): la política del motor rechaza una clave que contenga el nombre del login, y eso solo se nota en un motor con la política activa.

## Demostraciones manuales

- **SQL injection:** entrar como `admin` → *SQL injection*. Con `' OR 1=1--`, la versión vulnerable devuelve los 5 clientes y la parametrizada 0. El mismo filtro, dos procedimientos.
- **Inferencia DDM:** entrar como `ana` → *Inferencia DDM*. La tabla muestra `0.00`, pero “Probar umbral” responde si el saldo real supera un valor y “Recuperar saldo exacto” lo obtiene por búsqueda binaria (≈42 consultas).
- **Auditoría:** tras un acceso denegado, `sofia` ve en *Auditoría* la columna `succeeded` como insignia **denegado**.
- **Metadatos y ACL (B5):** `sofia` → *Metadatos y ACL*. Ve `VIEW DEFINITION = sí`, `CONTROL = no`, las 8 máscaras, la ACL completa por principal y el inventario de columnas con su tipo de cifrado. Es lectura: no puede cambiar nada.
- **Always Encrypted:** `ana` o `maria` → *Always Encrypted*. La misma fila aparece como texto claro en el panel “con Always Encrypted” y como base64 en el panel “sin Always Encrypted”; el formulario guarda con parámetros ya cifrados y la búsqueda por `CI` funciona porque es determinista. Con `admin` la pantalla muestra las claves y la negación del motor.
- **XMLDSig:** en *Firma digital*, “Firmar y verificar XML” devuelve el `<Signature>` embebido, el emisor de la CA, la raíz de confianza y `cadena_valida: true`.
- **Restauración en la misma instancia:** `sqlcmd -S localhost -d master -b -i app/sql/12_restauracion_prueba.sql`.
- **Restauración en otra instancia:** `bash tools/verificar-restauracion-otra-instancia.sh` — respalda cifrado, levanta un contenedor limpio, importa el certificado TDE por binario, restaura y verifica `ENCRYPTED · AES 256`, `DBCC CHECKDB`, conteos, firmas y `varbinary` en `ClientesAE`.
- **Comparación de cifrado:** `COMPARACION-CIFRADO.md` y `11_comparacion_cifrado.sql`, con las cuatro estrategias medidas.

## Pruebas

```bash
dotnet test tests/BancoAndino.Tests/BancoAndino.Tests.csproj
```

**24 pruebas** contra la app en memoria (`TestServer`, entorno `Testing`) y el SQL Server real. Cubren login PBKDF2, bloqueo tras cinco fallos, cookie `HttpOnly`, caducidad/revocación, salud autenticada, mínimos privilegios, `DENY` por columna (error 230), DDM enmascarado vs. real, descifrado permitido/denegado, TDE, firmas, XMLDSig con cadena de CA, inferencia, SQLi, auditoría con `succeeded = 0`, metadatos del auditor, **sesión que sobrevive a otro proceso**, **revocación global** y **Always Encrypted** (alta, búsqueda determinista, binario sin cliente y `403` al auditor).

Las pruebas comparten la base: su constructor limpia `IntentosFallidos`/`BloqueadoHasta` y la paralelización está desactivada para que una revocación global no interfiera con otra prueba. Detener la app antes de compilar en Windows (el `.exe` queda bloqueado).

## Mediciones de rendimiento de la sesión

`tools/mediciones/` reproduce las cifras de `DESARROLLO.md` §4 sobre el camino caliente de `dbo.SesionesApp`: la validación de sesión y el barrido de vencidas en el login.

> **No ejecutar contra una base con datos reales.** Los scripts vacían `dbo.SesionesApp`, cargan 20.000 sesiones sintéticas y crean o eliminan índices filtrados. Son para la base de laboratorio.

### Requisitos

- `sqlcmd` en el `PATH` y conexión por autenticación de Windows a `localhost` (los scripts no llevan credenciales).
- Un login con permisos de **`sysadmin` o `dbo`**: los scripts hacen `TRUNCATE TABLE`, `CREATE`/`DROP INDEX` y `UPDATE STATISTICS`. La cuenta de la aplicación (`app_bancoandino`) **no alcanza**: solo tiene `EXECUTE` sobre los `usp_Sesion*` y `SELECT`/`UPDATE` en `UsuariosApp`, sin DDL ni acceso directo a `SesionesApp`.
- La base `BancoAndino` creada hasta `app/sql/17_sesiones.sql`, con los procedimientos `usp_Sesion*` y sus índices.
- Bash (Git Bash en Windows): los `.sh` usan `MSYS2_ARG_CONV_EXCL='*'` para que `-S`, `-I` y `-W` no se conviertan en rutas.

### Qué mide cada script

| Script | Qué compara | Qué deja en el log |
| --- | --- | --- |
| `medir-sesiones.sh` | El diseño final (`IX_SesionesApp_Vigentes_Uso`) contra la línea base sin índices de vigentes | Lecturas lógicas y µs por llamada de `usp_SesionValidar` (1.000 llamadas) y del login (50 altas), sin y con 2.000 filas muertas |
| `medir-final.sh` | El diseño final: reaplica `17_sesiones.sql`, quita el índice de `Creada` y prueba la caducidad absoluta | Coste del `UPDATE … OUTPUT` y del barrido, más la salida de `10_final.sql`: validar una vencida devuelve 0, contar vigentes y el login que borra 1.000 filas |
| `medir-plan.sh` | El plan con y sin índices filtrados | Marcas del plan (`Index Seek`, `Clustered Index Update`, índices usados) y tamaño del XML |

Cada script escribe su log en `tools/mediciones/medicion*.log` (ignorado por git) y resume por pantalla solo las líneas de interés.

```bash
bash tools/mediciones/medir-final.sh     # estado final del repositorio
bash tools/mediciones/medir-sesiones.sh  # comparación de los tres estados
bash tools/mediciones/medir-plan.sh      # planes de ejecución
```

### Qué tocan en la base y cómo volver atrás

- `00_preparar.sql` copia las sesiones reales a `dbo.SesionesApp_med_respaldo` (solo si esa tabla no existe), vacía `SesionesApp` e inserta 20.000 filas sintéticas; `03_muertas.sql` envejece 2.000 de ellas para forzar el barrido.
- `05_restaurar.sql` devuelve las sesiones originales, borra el respaldo y actualiza estadísticas; los tres scripts lo ejecutan al final.
- Si una corrida se interrumpe, el respaldo sigue en la tabla y la base queda con sesiones sintéticas: `sqlcmd -S localhost -d BancoAndino -i tools/mediciones/05_restaurar.sql` la deja como estaba. Mientras tanto, las sesiones abiertas se pierden y hay que volver a entrar.

## Integración continua

`.github/workflows/ci-bancoandino.yml` levanta SQL Server 2022 en un contenedor Linux, crea la carpeta de auditoría, aplica `01`, `03`, `05`, `06`, `10`, `13`, `17`, `18`, `02` (con `AuditDir` de Linux), `40_tde_ci`, `50_seed_ci`, `14`, `15` y `16`, y corre las pruebas con el login **`app_bancoandino`** (no `sa`).

Como GitHub Actions no puede correr en esta cuenta, el mismo flujo está replicado y **verificado** en local:

```bash
bash tools/verificar-ci-local.sh
```

Levanta un contenedor limpio, aplica la secuencia completa y corre las 24 pruebas: `Correctas! 24/24`. Always Encrypted se omite en Linux (no hay almacén de certificados de Windows) y la prueba correspondiente verifica que el endpoint informa `disponible: false` en lugar de romper.

> Estado remoto: el job sigue sin ejecutarse porque la cuenta de GitHub está bloqueada por facturación (`github.com/settings/billing`). La lógica del workflow está validada en local (contenedor + 24/24), no en los servidores de GitHub.

## Mapa control → archivo

| Control | Dónde se implementa | Dónde se ve | Prueba |
| --- | --- | --- | --- |
| Matriz de protección, ACL y capacidades | `MATRIZ-DE-PROTECCION.md` | Metadatos y ACL | — |
| Mínimo privilegio y separación de funciones | `01_esquema.sql` §4, `13_admin_procs.sql`, `Program.cs` | Administración | `La_cuenta_de_aplicacion_no_es_sysadmin_ni_db_owner`, `El_dba_no_lee_datos_por_su_cuenta` |
| Permisos por columna | `01_esquema.sql` §4, `/api/datos/{tabla}` | Clientes / Empleados | `Cajero_lee_empleados_pero_no_la_columna_salario` |
| Metadatos y ACL para el auditor (B5) | `18_metadatos.sql`, `/api/metadatos` | Metadatos y ACL | `El_auditor_lee_la_acl_y_las_mascaras_sin_poder_cambiarlas` |
| SQLi comparada | `10_demo_sqli.sql`, `/api/demo/sqli` | SQL injection | `La_demo_de_sqli_muestra_la_diferencia` |
| Auditoría y accesos denegados | `02_auditoria.sql`, `14_auditoria_lector.sql`, `15_auditoria_objetos.sql`, `/api/auditoria` | Auditoría | `La_auditoria_registra_accesos_denegados` |
| Inferencia por `WHERE` | `/api/demo/inferencia`, `app.js` | Inferencia DDM | `Inferencia_por_umbral_revela_el_saldo_real` |
| Enmascaramiento dinámico (DDM) | `01_esquema.sql` §2, `usp_AdminMascara` | Clientes / Empleados / Administración | `Cajero_lee_empleados_pero_no_la_columna_salario` |
| Contraseñas PBKDF2 y rotación | `03_usuarios_app.sql`, `08_rotar_password_demo.sql`, `/api/login` | Acceso | `Login_con_clave_incorrecta_devuelve_401` |
| Bloqueo por fuerza bruta | `09_bloqueo_intentos.sql`, `/api/login` | Aviso de bloqueo | `La_cuenta_se_bloquea_tras_cinco_intentos_fallidos` |
| Sesión persistente, cookie y revocación | `17_sesiones.sql`, `Program.cs`, `/api/admin/revocar-sesiones` | Chip de usuario / Administración | `La_cookie_de_sesion_es_httponly_y_autentica`, `La_sesion_sobrevive_a_otro_proceso_de_la_aplicacion`, `La_revocacion_global_alcanza_a_otras_sesiones_y_procesos` |
| TLS y CSRF | Kestrel HTTPS `5443`, middleware de `Origin` | — | — |
| TDE y respaldo cifrado | `04_tde.sql`, `07_backup_antes_de_actualizar.sql`, `/api/cifrado` | Cifrado (TDE) | `La_base_esta_cifrada_con_TDE` |
| Cifrado por columna | `06_cifrado_columnas.sql`, `/api/columnas*` | Cifrado columnas | `Cajero_ve_los_datos_pero_no_puede_descifrar_la_tarjeta`, `Riesgos_puede_descifrar_la_tarjeta` |
| Always Encrypted | `tools/AeSetup`, `16_always_encrypted.sql`, `/api/ae/*` | Always Encrypted | `Always_encrypted_guarda_binario_y_descifra_solo_en_el_cliente` |
| Firma digital y XMLDSig | `05_firma_transacciones.sql`, `pki/crear-pki.ps1`, `/api/firma*` | Firma digital | `Las_transacciones_firmadas_informan_firma_e_integridad`, `La_firma_xmldsig_se_valida_contra_la_raiz_de_la_CA` |
| Restauración verificada | `12_restauracion_prueba.sql`, `tools/verificar-restauracion-otra-instancia.sh` | — | Verificación manual documentada |
| Comparación de cifrado | `11_comparacion_cifrado.sql`, `COMPARACION-CIFRADO.md` | — | — |
| Autorización de la app por rol | `Program.cs` (`s.Rol`), índice de `app.js` | Menú lateral | — |

### Endpoints

- `POST /api/login`, `POST /api/logout`, `GET /api/sesion` — sesión, cookie y permisos efectivos.
- `GET /api/datos/{clientes|transacciones|empleados}` — lectura suplantando al usuario de base.
- `GET /api/auditoria` — registros del audit (lector firmado); `GET /api/metadatos` — ACL, máscaras y columnas para `auditor` y `dba`.
- `GET /api/admin/estado`, `POST /api/admin/{permiso|mascara|usuario|revocar-sesiones}` — solo `dba`.
- `GET /api/demo/inferencia?clienteId=&umbral=` — conteo sobre el saldo real; `GET /api/demo/sqli?filtro=` — vulnerable vs. parametrizado (solo `dba`).
- `GET /api/cifrado`, `POST /api/cifrado/backup-certificado`; `GET /api/firma`, `GET /api/firma/xmldsig`, `POST /api/firma/{firmar|alterar|restaurar}`; `GET /api/columnas`, `POST /api/columnas/{guardar|descifrar}`.
- `GET /api/ae/estado`, `GET /api/ae/clientes`, `GET /api/ae/buscar?ci=`, `POST /api/ae/guardar` — Always Encrypted (cajero y riesgos; el resto recibe `403`).
- `GET /api/salud` — **requiere token**; devuelve base, login de conexión y versión del motor.

## Estructura

```
INFORME.md                Informe del proyecto (entregable de la materia)
DESARROLLO.md             Cierre del desarrollo: limitaciones, mediciones y decisiones
MATRIZ-DE-PROTECCION.md   Fase 1: sujetos × objetos, ACL y capacidades
COMPARACION-CIFRADO.md    TDE vs. columna vs. frase de paso vs. Always Encrypted
app/                      API mínima + frontend estático
  Program.cs              endpoints, login PBKDF2, sesión en base, TLS, suplantación, XMLDSig
  wwwroot/                index.html, styles.css, app.js
  sql/                    01→18 modelo de seguridad
  sql/ci/                 variantes para el contenedor de integración continua
pki/                      scripts de CA y CMK (las claves generadas no se versionan)
tools/                    AeSetup, verificaciones de restauración y CI, y arnés de medición
tests/                    xUnit contra la app en memoria (24)
.github/workflows/        CI con SQL Server en contenedor
api.http                  peticiones manuales
```

## Límites que subsisten

1. **Secretos de demostración en scripts SQL** (clave de la DMK, contraseña del respaldo del certificado y claves de las cuentas). Son de laboratorio y están en el repo; en producción van a un almacén de secretos y se rotan.
2. **El lector de auditoría firmado tiene `CONTROL SERVER`** (`CertAuditoriaLogin`). Es la única forma de que `fn_get_audit_file` funcione sin dárselo a la app, pero el procedimiento es un objeto de alto valor: su uso se audita desde `AuditSpec_LectorFirmado` (`15_auditoria_objetos.sql`) y su firma debe revisarse al cambiarlo.
3. **Always Encrypted depende del almacén de certificados de Windows.** Para Linux o nube hay que cambiar el proveedor a Azure Key Vault; las columnas, la CEK y la app no cambian. Además protege del motor y del backup, no del proceso que abre la CMK.
4. **La CA de firma es local.** El camino criptográfico (certificado emitido por una CA, cadena validada con `CustomRootTrust`) es el de producción; el certificado lo emite `pki/crear-pki.ps1`, no una CA pública. La app informa `origen` y `emisor` para que no se confunda con uno emitido por una CA externa.
5. **La corrida remota del CI depende de la facturación de GitHub.** Todas las corridas registradas están en `failure`: el job no llega a arrancar (sin runner asignado, sin pasos y sin log), así que el bloqueo es de la cuenta, no del workflow. La lógica está replicada y validada en local con `tools/verificar-ci-local.sh` (24/24 sobre un contenedor limpio).
