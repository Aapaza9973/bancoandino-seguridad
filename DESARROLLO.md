# BancoAndino — desarrollo completo

Documento de cierre del proyecto de **Seguridad Informática**: una consola ASP.NET Core 9 contra **SQL Server 2022** donde los controles los aplica el motor, no el código. Cada consulta viaja como el usuario de base que corresponde (`EXECUTE AS USER`), así que lo que se ve en pantalla es el veredicto real de SQL Server: lo que concede, lo que enmascara y lo que niega.

Repositorio: `github.com/Aapaza9973/bancoandino-seguridad` · rama `main`, nueve commits por encima del punto de partida, sincronizada con `origin/main`.

## 1. Punto de partida y objetivo

El proyecto arrancaba con la matriz de protección documentada y una aplicación que se conectaba como `sa`. Faltaba lo que hace que un modelo de seguridad sea real: que el motor sea quien decida. El trabajo se organizó en dos frentes:

1. **Cerrar las brechas declaradas** (B1–B6 de la matriz) y las seis limitaciones que el README admitía como deuda.
2. **Dejar el resultado en el repositorio**, en commits lógicos que compilen por separado.

Seis commits de código, cada uno compilado en un `git worktree` temporal antes de existir:

| Commit | Qué cierra |
| --- | --- |
| `4354da4` | Mínimo privilegio: `app_bancoandino` sin `sysadmin` ni `db_owner`, `IMPERSONATE`, `DENY` por columna, PBKDF2, respaldo cifrado, rotación de claves de logins |
| `3d9759b` | Scripts que la interfaz ya llamaba pero no estaban versionados: demo de SQLi, comparación de cifrado, restauración, administración, lector de auditoría |
| `6718275` | Las seis limitaciones: Always Encrypted real, B5, sesiones en base, CA XMLDSig, restauración en otra instancia, pruebas y documentación |
| `d685a1d` | Validación de sesión con una sola escritura y conteo que excluye vencidas |
| `3876e49` | Integración continua con el modelo completo y el login de la aplicación |
| `6d29444` | Índices filtrados del barrido del login, medidos y acotados a lo que se justifica |

## 2. Arquitectura del modelo de seguridad

Todo vive en `BancoAndino` y se construye con dieciocho scripts idempotentes en `app/sql`:

| Bloque | Scripts | Qué hace |
| --- | --- | --- |
| Esquema y permisos | `01` | Tablas, datos, máscaras DDM, logins, roles, permisos por columna y `DENY` explícitos |
| Auditoría | `02`, `14`, `15` | Server audit a archivo; lector firmado por `CertAuditoria`; objetos auditados |
| Cuentas | `03`, `08`, `09` | PBKDF2-HMAC-SHA256 (210.000 iteraciones, sal de 16 bytes), rotación y bloqueo por intentos |
| Cifrado en reposo | `04`, `07` | TDE, certificado de servidor, respaldo cifrado con AES-256 |
| Firma | `05` | Documentos firmados, alteración/restauración y vista de integridad |
| Cifrado por columna | `06`, `11` | AES-256 con clave simétrica y frase de paso, para comparar estrategias |
| Demos | `10`, `12` | SQLi vulnerable vs. parametrizada; restauración verificada |
| Administración | `13` | `usp_AdminPermiso` y `usp_AdminMascara` con `EXECUTE AS OWNER` |
| Always Encrypted | `16`, `tools/AeSetup` | CMK en `CurrentUser\My`, CEK RSA-OAEP, tabla con columnas deterministas y aleatorias |
| Sesiones | `17` | `dbo.SesionesApp` con SHA-256 del token y cinco procedimientos |
| Metadatos | `18` | `VIEW DEFINITION` para `rol_auditor` y verificación en su contexto |

La aplicación se conecta como **`app_bancoandino`**, sin roles fijos: `IMPERSONATE` sobre los cinco usuarios de demostración, `EXECUTE` acotado y `CONTROL` solo sobre el certificado TDE. `dba_admin` tampoco es `db_owner`: administra a través de procedimientos y no puede leer las tablas de negocio.

## 3. Las seis limitaciones, antes y ahora

| Limitación original | Estado | Cómo quedó | Evidencia verificada |
| --- | --- | --- | --- |
| Always Encrypted solo documentado | **Cerrada** | CMK real en `CurrentUser\My` con clave no exportable; CEK cifrada con RSA-OAEP; `dbo.ClientesAE` con `CI` determinista y columnas aleatorias; dos cadenas de conexión para comparar claro vs. binario | CEK de 627 bytes con `RSA_OAEP`, columna `varbinary(65)`, búsqueda por `CI` `8765432` devuelve 1 fila, `dba` recibe 403 |
| Sesiones en memoria del proceso | **Cerrada** | `dbo.SesionesApp` guarda el SHA-256 del token; caducidad deslizante (30 min) y absoluta (8 h) evaluadas por el motor | La sesión sobrevive a otro proceso; la revocación global alcanza a las demás |
| Certificado XMLDSig efímero | **Cerrada (CA local)** | `pki/crear-pki.ps1` emite desde una CA raíz; la app valida con `X509Chain` + `CustomRootTrust` y cae a efímero solo si falta la CA | `valida=True`, `cadena_valida=True`, emisor `CN=BancoAndino Root CA` |
| Restauración solo en la misma instancia | **Cerrada** | `tools/verificar-restauracion-otra-instancia.sh`: contenedor limpio con su propia SMK, certificado TDE viajando como `CERTENCODED`/`CERTPRIVATEKEY` | `ENCRYPTED · AES 256`, `DBCC CHECKDB`, conteos, firmas y `varbinary` en `ClientesAE` |
| Auditor sin metadatos (B5) | **Cerrada** | `GRANT VIEW DEFINITION TO rol_auditor` y `/api/metadatos` en el contexto del auditor | `VIEW DEFINITION=True`, `CONTROL=False`, 8 máscaras, cajero 403 |
| CI sin corridas | **Validado en local** | El workflow replica la secuencia completa con `app_bancoandino` y `AuditDir` de Linux | `tools/verificar-ci-local.sh`: contenedor limpio, **24/24** |

También se cerraron B1–B6 (DBA sin `db_owner`, conexión sin `sysadmin`, controles en el motor, sin *fallback* de descifrado, metadatos para el auditor, `CHECK_POLICY = ON` con PBKDF2) y se corrigió un defecto encontrado en revisión: `usp_SesionRevocarTodas` contaba como revocadas las sesiones ya vencidas (con 11 filas y 2 vencidas informaba 11; ahora informa 9).

## 4. El camino caliente de la sesión

La primera versión borraba sesiones vencidas en **cada request autenticado**: con 20.000 sesiones eran 511 lecturas lógicas y unos 10 ms por llamada, aunque no hubiera nada que borrar. El commit `d685a1d` movió la limpieza al login y dejó la caducidad en el `WHERE` de un `UPDATE … OUTPUT` sobre la PK: 9 lecturas y ~0,05 ms.

El commit `6d29444` volvió a medir ese mismo camino con los índices filtrados puestos, porque ahora el `UPDATE` mantiene un índice en cada request:

| Escenario (20.000 sesiones) | Lecturas lógicas | Composición |
| --- | --- | --- |
| Con `IX_SesionesApp_Vigentes_Uso` | **9** | 3 búsqueda en el clustered + 3 en el índice filtrado + 3 de mantenimiento |
| Sin ningún índice filtrado | **3** | solo la búsqueda por PK |
| Tiempo por llamada | 0,35 vs. 0,34 ms | dentro del ruido del arnés |

El índice cuesta 6 lecturas por request y no se nota en tiempo; se queda porque el barrido del login pasa de 524 páginas a 4 lecturas. Lo que no se pudo reproducir es que *sin* índices diera 9: hoy esa sentencia sin índices lee 3, así que las 9 de la medición anterior no salían del mismo estado.

### El barrido del login, medido y recortado

| Estado | Lecturas | Tiempo/login |
| --- | --- | --- |
| `Uso` + `Creada` (dos índices, tres `DELETE`) | 0 + 4 + 3 + 15 = **22** | 0,26 ms |
| **Final: solo `Uso`** | 0 + 3 + 12 = **15** | 0,25–0,31 ms |
| `Uso`, sin índice de `Creada` pero con su `DELETE` | 0 + 4 + **524** + 12 = 540 | 8,4 ms |
| Sin ningún índice filtrado | 0 + **524** + **524** + 9 = 1.057 | 16,3 ms |

La tercera fila es la que decide: el `DELETE` por `Creada` **necesita** su índice o recorre la tabla. Aun teniéndolo, aportaba 3 lecturas por login más 3 en cada `INSERT`, y con 2.000 filas muertas los dos borrados costaban 12.087 + 12.085 lecturas frente a 9.085 con uno solo. Se quitó `IX_SesionesApp_Vigentes_Creada` y su `DELETE`.

**Por qué es seguro:** la caducidad absoluta ya se evalúa en el `WHERE` de `usp_SesionValidar` y de `usp_SesionContar`; una sesión vencida deja de renovarse, su `UltimoUso` se congela y el barrido deslizante la alcanza dentro de los 30 minutos siguientes. Verificado con 20.000 filas y 2.000 muertas: tras el login quedan 19.001 (las 1.000 absolutamente vencidas con uso reciente siguen en la tabla), `usp_SesionValidar` sobre una de ellas devuelve 0 filas y `usp_SesionContar` informa 18.000 vigentes; al envejecer su `UltimoUso`, el siguiente login las borra (19.001 → 18.002).

## 5. Decisiones y hallazgos

- **Un `OR` anula el índice.** Un único índice filtrado no sirve para `(UltimoUso < …) OR (Creada < …)`: el motor sigue recorriendo la tabla. Hubo que partir el barrido en borrados separados.
- **Un índice compuesto tampoco.** Con `(UltimoUso, Creada)` el barrido quedaba en 506 lecturas y 328 páginas; separado por caducidad bajó a 95 lecturas y 0,96 ms, con 17 lecturas en régimen estable.
- **`QUOTED_IDENTIFIER`.** Los índices filtrados exigen `ANSI_NULLS` y `QUOTED_IDENTIFIER` en `ON` al crearse y al usarse; `sqlcmd` viene con `OFF`, así que el script los fija al inicio y las invocaciones llevan `-I`.
- **La política del motor rechaza claves que contienen el nombre del login.** Se descubrió solo en el contenedor Linux; las claves de los logins de base se rotaron por eso.
- **`EXEC proc @p = CONVERT(...)` no es T-SQL válido:** el valor se asigna primero a una variable.
- **Revisión de código:** `usp_SesionRevocarTodas` contaba como revocadas las sesiones ya vencidas; con 11 filas y 2 vencidas informaba 11, ahora informa 9.

## 6. Pruebas y verificaciones ejecutadas

| Comprobación | Resultado |
| --- | --- |
| `dotnet test` sobre SQL Server real | **24/24** |
| `tools/verificar-ci-local.sh` en contenedor limpio | **24/24** |
| Login real tras el último cambio | `ana` 200, `/api/sesion` 200, el barrido borró 2 filas vencidas |
| Always Encrypted | CEK RSA-OAEP de 627 bytes, `varbinary(65)`, búsqueda por `CI` → 1 fila, `dba` 403 |
| Metadatos del auditor | `VIEW DEFINITION=True`, `CONTROL=False`, 8 máscaras |
| Firma XMLDSig | `valida=True`, `cadena_valida=True`, `CN=BancoAndino Root CA` |
| Restauración en otra instancia | `ENCRYPTED · AES 256`, `DBCC CHECKDB`, conteos, firmas |

Las mediciones de rendimiento se reproducen con los scripts de `.tmp/` (ignorado por git): cargan 20.000 sesiones sintéticas, conservan un respaldo de las reales y comparan estados de índices.

## 7. Límites que subsisten

1. **Secretos de demostración en scripts SQL** (clave de la DMK, contraseña del respaldo del certificado, claves de las cuentas). Son de laboratorio; en producción van a un almacén de secretos y se rotan.
2. **El lector de auditoría firmado tiene `CONTROL SERVER`.** Es la única forma de que `fn_get_audit_file` funcione sin dárselo a la app, pero el procedimiento es un objeto de alto valor y debe auditarse.
3. **Always Encrypted depende del almacén de certificados de Windows.** En Linux/CI no está (`MSSQL_CERTIFICATE_STORE`); el script avisa y la prueba verifica `disponible: false` en lugar de romper.
4. **La CA de firma es local.** El camino criptográfico es el de producción, pero el certificado lo emite `pki/crear-pki.ps1`, no una CA pública.
5. **La corrida remota del CI depende de la facturación de GitHub.** La cuenta está bloqueada; el flujo está replicado y validado en local.

## 8. Cómo reproducir

```bash
# 1) Base y modelo (como sysadmin, en orden)
sqlcmd -S localhost -i app/sql/01_esquema.sql
sqlcmd -S localhost -i app/sql/02_auditoria.sql -v AuditDir='C:\AuditLogs\BancoAndino\'
# … 03 a 18

# 2) Claves del cliente
powershell -NoProfile -ExecutionPolicy Bypass -File pki/crear-pki.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File pki/crear-cmk.ps1
dotnet run --project tools/AeSetup

# 3) Cadena de conexión en user-secrets y arranque
dotnet run --project app          # http://127.0.0.1:5080

# 4) Pruebas y verificaciones
dotnet test tests/BancoAndino.Tests/BancoAndino.Tests.csproj
bash tools/verificar-ci-local.sh
bash tools/verificar-restauracion-otra-instancia.sh
```

## 9. Estado del repositorio

- `main` con **nueve commits** por encima del punto de partida (`4d167a7`), todos publicados en `origin/main`: seis de código, dos que agregan este documento y el que lo da de alta en el README.
- Árbol de trabajo limpio y sincronizado con `origin/main`.
- La aplicación corre en `http://127.0.0.1:5080` con el preview abierto.
- Documentación viva en el repo: `README.md` (puesta en marcha, mapa control → archivo, endpoints), este `DESARROLLO.md` (cierre, mediciones y decisiones), `MATRIZ-DE-PROTECCION.md` (§16 cierre de brechas) y `COMPARACION-CIFRADO.md`.
