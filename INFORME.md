# Informe del proyecto — Banco Andino

**Materia:** Seguridad Informática · **Instancia:** SQL Server 2022 Developer, base `BancoAndino` · **Aplicación:** ASP.NET Core 9 · **Fecha:** 28 de noviembre de 2026 · **Repositorio:** `github.com/Aapaza9973/bancoandino-seguridad` (rama `main`)

## Resumen ejecutivo

El proyecto construye una consola de seguridad sobre una base bancaria ficticia donde **los controles los aplica el motor de base de datos, no el código de la aplicación**. Cada petición se ejecuta suplantando al principal de base del usuario (`EXECUTE AS USER`), de modo que lo que la interfaz muestra —lo concedido, lo enmascarado y lo negado— es el veredicto real de SQL Server.

Sobre una única base se demuestran y verifican: matriz de protección con ACL y capacidades, mínimo privilegio efectivo (la aplicación no es `sysadmin` ni `db_owner`), permisos por columna, enmascaramiento dinámico y su inferencia por `WHERE`, inyección SQL comparada, auditoría a archivo con accesos denegados, TDE, cifrado por columna, frase de paso, Always Encrypted con la clave maestra fuera del motor, firma digital con cadena de CA, contraseñas PBKDF2, sesión persistida en la base con revocación global, y restauración verificada en otra instancia.

**Resultado:** 24 pruebas automatizadas en verde (24/24 también en un contenedor limpio), las seis brechas de privilegios cerradas y seis limitaciones documentadas resueltas. El trabajo quedó en la rama `main`, con la documentación del repositorio actualizada.

## 1. Introducción

### 1.1 Problema

Una aplicación que decide permisos en su propio código no protege nada: cualquiera con acceso a la base, a un respaldo o a una consola de administración la rodea. El caso Banco Andino parte de ese defecto —una aplicación conectada como `sa`— y lo corrige en el único lugar donde el control es exigible: el motor.

### 1.2 Objetivos

**General.** Diseñar, implementar y verificar un modelo de protección de datos bancarios donde cada derecho se ejerza con el mínimo privilegio y pueda auditarse.

**Específicos.**

1. Formalizar la matriz sujeto × objeto y derivarla a ACL y lista de capacidades.
2. Llevar esa matriz al motor: logins sin roles fijos, `IMPERSONATE`, `DENY` por columna, procedimientos con `EXECUTE AS OWNER` y firmas de módulo.
3. Cubrir el dato en tránsito, en reposo y en uso, y demostrar la diferencia entre las cuatro estrategias de cifrado de SQL Server.
4. Persistir la sesión fuera del proceso, con caducidad y revocación evaluadas por la base.
5. Verificar cada control con pruebas ejecutables y con mediciones, no con afirmaciones.

### 1.3 Alcance

Quedan dentro la base, sus objetos, los principales y la aplicación. Quedan fuera la red, el sistema operativo, la alta disponibilidad y la operación real del banco.

## 2. Marco de referencia

Se aplican los conceptos de dominios de protección y matrices de acceso: cada sujeto es un dominio, cada objeto protegido tiene un conjunto de derechos (lectura, escritura, ejecución, borrado, control) y el derecho *switch* —`IMPERSONATE`— permite al proceso de la aplicación **cambiar de dominio** en vez de acumular permisos.

De ahí se derivan las dos representaciones que el proyecto mantiene sincronizadas:

- **ACL por objeto**: qué sujetos y con qué derechos alcanzan cada tabla, vista, procedimiento, clave o certificado.
- **Lista de capacidades por sujeto**: qué puede hacer cada rol, incluido lo que se le niega a propósito.

La regla de diseño que ordena todo el modelo es la **separación de funciones**: quien administra la estructura no lee el contenido, quien lee no administra, y quien audita no puede alterar el registro.

## 3. Arquitectura de la solución

La solución tiene tres capas con una frontera de confianza explícita:

| Capa | Componente | Responsabilidad |
| --- | --- | --- |
| Cliente | `app/wwwroot` (HTML/CSS/JS) | Presenta el veredicto del motor; no decide permisos |
| Aplicación | `app/Program.cs` | Autentica (PBKDF2), abre la conexión como `app_bancoandino`, suplanta al usuario, aplica TLS y CSRF, y expone la API |
| Motor | 18 scripts en `app/sql` + `pki/` + `tools/AeSetup` | Aplica permisos, máscaras, cifrado, auditoría, sesiones y firma |

El proceso de la aplicación **no lee las tablas de negocio por su cuenta**: para cada consulta cambia de dominio con `EXECUTE AS USER` y deja que SQL Server conceda o niegue. Los chequeos de rol en el código quedan como defensa en profundidad, nunca como única barrera.

## 4. Diseño del modelo de protección

### 4.1 Sujetos

| Sujeto | Principal | Rol en el banco |
| --- | --- | --- |
| Cajero | `cajero_ana` | Atención al público |
| Supervisor | `supervisor_luis` | Supervisión de caja |
| Riesgos | `riesgos_maria` | Análisis de fraude; único con datos reales y descifrado |
| Auditor | `auditor_sofia` | Auditoría interna: lee, no opera |
| DBA | `dba_admin` | Administra sin leer el contenido |
| Proceso | `app_bancoandino` | Suplanta; no consulta datos por su cuenta |

### 4.2 Matriz implementada (resumen)

| Sujeto | Clientes | Transacciones | Empleados | Tarjetas | Auditoría | Claves | Metadatos |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Cajero | `L*` | `L` | `L*` sin `Salario` | `L`, descifra | — | — | — |
| Supervisor | `L*` sin `NumeroTarjeta` | `L` | — | `L`, descifra | — | — | — |
| Riesgos | `L` | `L` | `L` | `L`, descifra | — | `C` | — |
| Auditor | `L*` | `L` | `L*` | `L` | `L` (por procedimiento firmado) | — | `L` |
| DBA | — | — | — | — | — | — | `L` |
| Proceso | — | — | — | guarda | lee (firmado) | — | `L` |

`L*` es lectura enmascarada por DDM. **Ningún sujeto tiene escritura ni borrado directo sobre las tablas de negocio**: las altas de tarjeta y la firma pasan por procedimientos, y la auditoría solo la escribe el motor.

### 4.3 Denegaciones deliberadas

El valor del modelo está en lo que se niega, no solo en lo que se concede:

- El **DBA** no tiene `CONTROL` sobre los datos ni sobre la clave de tarjetas: administra permisos y máscaras a través de `usp_AdminPermiso`/`usp_AdminMascara` con `EXECUTE AS OWNER`.
- La **aplicación** no tiene `SELECT` sobre `Clientes`, `Transacciones` ni `Empleados`; solo `IMPERSONATE`.
- El **supervisor** recibe error 230 al pedir la columna `NumeroTarjeta`.
- El **auditor** ve metadatos y ACL (`VIEW DEFINITION`) pero no `CONTROL`, y no descifra.
- El **cajero** ve `Empleados` salvo `Salario`, y recibe `403` al intentar descifrar una tarjeta.

## 5. Implementación por control

| Control | Mecanismo real | Artefacto |
| --- | --- | --- |
| Mínimo privilegio | Login sin roles fijos, `IMPERSONATE`, `EXECUTE` acotado, `CONTROL` solo sobre el certificado TDE | `01_esquema.sql` |
| Permisos por columna | `DENY SELECT` sobre `Salario` y `NumeroTarjeta` | `01_esquema.sql` §4 |
| Enmascaramiento (DDM) | `MASKED WITH (FUNCTION=…)` y `UNMASK` para riesgos | `01_esquema.sql` §2 |
| Administración sin `CONTROL` | Procedimientos con `EXECUTE AS OWNER` | `13_admin_procs.sql` |
| Auditoría | Server audit a archivo con `QUEUE_DELAY = 0`; lector firmado por `CertAuditoria`, cuyo uso se audita | `02`, `14`, `15` |
| Contraseñas | PBKDF2-HMAC-SHA256, 210.000 iteraciones, sal de 16 bytes | `03`, `08` |
| Fuerza bruta | Contador y ventana de bloqueo por cuenta | `09` |
| Cifrado en reposo | TDE con AES-256 y respaldo cifrado | `04`, `07` |
| Cifrado por columna | AES-256 con clave simétrica y `CONTROL` sobre el certificado | `06` |
| Always Encrypted | CMK no exportable en el cliente, CEK RSA-OAEP, columnas deterministas y aleatorias | `pki/crear-cmk.ps1`, `tools/AeSetup`, `16` |
| Firma e integridad | RSA sobre hash SHA-256 y XMLDSig validado con `CustomRootTrust` | `05`, `pki/crear-pki.ps1` |
| Sesión | SHA-256 del token en `dbo.SesionesApp`; caducidad y revocación en el `WHERE` | `17` |
| Metadatos del auditor | `GRANT VIEW DEFINITION` y endpoint en su contexto | `18` |
| Restauración | `RESTORE VERIFYONLY`, `DBCC CHECKDB` y verificación en contenedor limpio | `12`, `tools/verificar-restauracion-otra-instancia.sh` |

## 6. Resultados

### 6.1 Cifrado

| Estrategia | Qué protege | Quién ve el dato en claro | Estado en el proyecto |
| --- | --- | --- | --- |
| TDE | Archivos y respaldos | El motor | Activo: `ENCRYPTED · AES · 256` |
| Columna con clave simétrica | La celda de tarjeta | El motor al descifrar; la app solo con `CONTROL` | Activo: riesgos descifra, cajero recibe error del motor |
| Frase de paso | Una celda aislada | Quien conozca la frase | Demostración: frase correcta devuelve el texto, incorrecta `NULL` |
| Always Encrypted | La columna completa, también frente al DBA | Solo el cliente que abre la CMK | Activo: `sqlcmd` ve `varbinary(65)`; la app ve `8765432 · Ana Quispe · 15.420,50` |

Always Encrypted quedó con CMK `CN=CMK_BancoAndino` en `CurrentUser\My` (clave privada no exportable) y CEK de 32 bytes cifrada con RSA-OAEP en 627 bytes. La búsqueda por igualdad funciona solo sobre `CI`, la columna determinista; nombre, saldo y tarjeta son aleatorias y no admiten filtros.

### 6.2 Acceso y sesión

| Comprobación | Resultado |
| --- | --- |
| Conexión de la aplicación | `app_bancoandino`, sin `sysadmin` ni `db_owner` |
| DBA leyendo datos | `403` |
| Supervisor pidiendo `NumeroTarjeta` | Error 230 del motor |
| Cajero pidiendo `Salario` | Error 230 del motor |
| Auditor pidiendo metadatos | `VIEW DEFINITION = sí`, `CONTROL = no`, 8 máscaras |
| Sesión tras reiniciar el proceso | Sigue válida (vive en la tabla) |
| Revocación global | Alcanza a otras sesiones y procesos |
| Auditoría de un acceso denegado | `succeeded = 0`, visible como insignia «denegado» |

### 6.3 Rendimiento de la validación de sesión

La primera versión limpiaba sesiones vencidas en cada petición autenticada: **511 lecturas lógicas y ~10 ms** con 20.000 sesiones, aunque no hubiera nada que borrar. Se movió la limpieza al login y la caducidad al `WHERE`, con una sola escritura sobre la PK: **9 lecturas y ~0,05 ms**.

Al añadir el índice filtrado que sostiene el barrido, la misma sentencia cuesta **9 lecturas** (3 de búsqueda en el clustered, 3 en el índice y 3 de mantenimiento) frente a 3 sin ningún índice filtrado; la diferencia de tiempo (0,35 vs. 0,34 ms por llamada) está dentro del ruido del arnés.

En el login, el barrido pasó de **22 lecturas** con dos índices filtrados a **15** con uno solo, tras comprobar que el segundo índice y su `DELETE` no se pagaban: sin ese índice el borrado recorre 524 páginas y el login sube a 540 lecturas y 8,4 ms; sin ningún índice, a 1.057 lecturas y 16,3 ms.

**Decisión:** conservar solo el índice sobre `UltimoUso` (`WHERE Revocada = 0`) y el de revocadas. La caducidad absoluta se sigue rechazando en el `WHERE` de validar y contar; una sesión vencida deja de renovarse y el barrido deslizante la alcanza en menos de 30 minutos. Verificado: con 2.000 filas muertas el login baja de 12.087 + 12.085 lecturas a 9.085, y las 1.000 absolutamente vencidas se borran en el login siguiente (19.001 → 18.002).

El arnés que produce estas cifras está versionado en `tools/mediciones/` (`medir-sesiones.sh`, `medir-final.sh`, `medir-plan.sh` y sus scripts SQL), así que las mediciones se reproducen desde un clon.

### 6.4 Verificación automatizada

24 pruebas contra la aplicación en memoria (`TestServer`) y el SQL Server real, en dos archivos: `ApiTests.cs` (19) y `LimitacionesTests.cs` (5). Cubren login PBKDF2 y bloqueo, cookie `HttpOnly`, 401 sin token, permisos por columna, DDM real vs. enmascarado, descifrado permitido y denegado, TDE, firmas, XMLDSig con CA, inferencia, SQLi, auditoría con denegados, metadatos del auditor, sesión entre procesos, revocación global y Always Encrypted.

Resultado: **24/24** en la instancia local y **24/24** en un contenedor limpio con `tools/verificar-ci-local.sh`. Always Encrypted se omite en Linux por falta del almacén de certificados; la prueba correspondiente verifica que el endpoint informa `disponible: false` en lugar de romper.

## 7. Discusión

**El motor como frontera de confianza simplifica la aplicación.** Al no tener `SELECT` sobre las tablas de negocio, la app no puede filtrar datos aunque tenga un defecto: solo puede suplantar a un usuario y recibir lo que ese usuario vería. El código conserva chequeos de rol, pero ya no son la única barrera.

**Lo que se niega vale más que lo que se concede.** El DBA sin `CONTROL` sobre los datos y sin lectura del contenido; la aplicación sin acceso directo; el auditor sin capacidad de cambio. Cada una de esas negaciones está respaldada por una prueba que espera el error del motor, no un mensaje de la interfaz.

**El cifrado no es una decisión única.** TDE protege archivos y respaldos sin tocar la aplicación, y es la base. El cifrado por columna protege la tarjeta incluso si alguien lee la tabla, a costa de procedimientos y de `CONTROL` sobre el certificado. La frase de paso demuestra el concepto pero no sirve para datos recuperables: la frase *es* la clave. Always Encrypted es la única capa que deja al motor sin texto claro, y por eso es la respuesta cuando el requisito es «ni el DBA ve el dato».

**El rendimiento se mide, no se supone.** La validación pasó de 511 lecturas a 9, y el barrido del login se recortó de 22 a 15 lecturas tras comprobar que el segundo índice filtrado costaba más de lo que ahorraba. La conclusión operativa es que **borrar en masa es más barato por recorrido que por búsqueda**: eliminar 1.000 filas por `seek` cuesta unas 9.000 lecturas, mientras que un recorrido completo son 524.

**Hallazgos técnicos que cambiaron el diseño:**

- Un `OR` entre dos condiciones de caducidad anula el índice filtrado: hubo que partir el barrido en borrados separados.
- Un índice compuesto `(UltimoUso, Creada)` dejaba 506 lecturas y 328 páginas; separado por caducidad bajó a 95 lecturas y 0,96 ms, con 17 lecturas en régimen estable.
- Los índices filtrados exigen `ANSI_NULLS` y `QUOTED_IDENTIFIER` en `ON`; `sqlcmd` viene con `OFF`, así que los scripts lo fijan y las invocaciones usan `-I`.
- La política de contraseñas del motor rechaza claves que contienen el nombre del login; se detectó solo en el contenedor Linux y obligó a rotar las claves de base.
- La revisión encontró que `usp_SesionRevocarTodas` contaba como revocadas las sesiones ya vencidas (11 filas, 2 vencidas, informaba 11); ahora informa 9.

**Tensión asumida en la auditoría.** Para leer el archivo de auditoría sin dar `CONTROL SERVER` a la aplicación se firmó un procedimiento con un certificado que sí lo tiene. Es un objeto de alto valor, así que su uso quedó dentro de la especificación de auditoría: cada `EXECUTE` sobre `usp_LeerAuditoria` se registra con el principal que lo invocó.

## 8. Limitaciones y trabajo futuro

| Limitación | Impacto | Camino de cierre |
| --- | --- | --- |
| Secretos de demostración en los scripts (DMK, respaldo del certificado, cuentas) | Aceptable en laboratorio | Almacén de secretos y rotación |
| Always Encrypted depende del almacén de certificados de Windows | No corre en Linux ni en la nube | Cambiar el proveedor a Azure Key Vault; columnas, CEK y app no cambian |
| La CA de firma es local | No acredita identidad ante terceros | Emitir el certificado desde una CA reconocida |
| La corrida remota del CI no llega a ejecutarse | El job no arranca en GitHub | Reactivar la cuenta; la lógica ya está validada en local (24/24) |

Dos limitaciones que este informe listaba al principio quedaron cerradas al preparar la entrega:

- **El lector de auditoría firmado** ya no es un objeto opaco: `15_auditoria_objetos.sql` añade `EXECUTE` sobre `dbo.usp_LeerAuditoria` a una especificación de base en `master` (`AuditSpec_LectorFirmado`), verificado en `sys.database_audit_specification_details` y con una ejecución real del lector registrada en el archivo de auditoría.
- **Las mediciones de rendimiento** salieron de `.tmp/`: el arnés vive en `tools/mediciones/`, con rutas relativas correctas y verificado con `bash -n`.

Sobre el CI remoto, la evidencia es concreta: el repositorio acumula 15 corridas, todas en `failure`, y la última (#11, commit `fe947cf`) terminó en dos segundos con el job **sin runner asignado** (`runner_id: 0`), sin pasos ejecutados y sin log descargable (`BlobNotFound`). No es un fallo del workflow: el trabajo nunca empieza, porque la cuenta está bloqueada por facturación. Con la cuenta al día, el mismo archivo debería correr sin cambios, ya que su secuencia está replicada y verificada en local.

Trabajo futuro natural: extender la matriz a la red y al sistema operativo (hoy fuera de alcance), añadir un segundo nodo de aplicación para ejercitar la sesión compartida, y sustituir el almacén de certificados por Key Vault para poder correr Always Encrypted en el CI.

## 9. Conclusiones

1. **Es posible mover los controles al motor sin perder funcionalidad.** La consola conserva todas sus pantallas porque cada una consulta con la identidad correcta; lo que cambió es quién decide.
2. **El mínimo privilegio es verificable.** Las seis brechas (B1–B6) quedaron cerradas con declaraciones concretas y pruebas que esperan el error del motor.
3. **Las cuatro estrategias de cifrado tienen lugar distinto.** El proyecto no elige una: las implementa, mide y documenta, y usa cada una donde corresponde.
4. **La sesión persistida elimina una clase de fallo.** Reiniciar el proceso ya no cierra sesiones, y la revocación global es una operación de base, no un estado en memoria.
5. **La documentación es parte del trabajo.** `README.md`, `MATRIZ-DE-PROTECCION.md`, `COMPARACION-CIFRADO.md` y `DESARROLLO.md` describen el mismo sistema desde ángulos distintos, y se actualizan en el mismo commit que el cambio que las motiva.

El resultado es un sistema donde la pregunta «¿puede este usuario ver este dato?» se responde ejecutando una consulta, no leyendo el código de la aplicación.

## 10. Anexos

### 10.1 Reproducción

1. Ejecutar `app/sql/01` a `18` como `sysadmin` (con `-I` y `-v AuditDir='C:\AuditLogs\BancoAndino\'`).
2. Generar las claves del cliente: `pki/crear-pki.ps1` y `pki/crear-cmk.ps1`; luego `dotnet run --project tools/AeSetup`.
3. Guardar la cadena de conexión en user-secrets y arrancar `dotnet run --project app` (`http://127.0.0.1:5080`).
4. Verificar: `dotnet test`, `tools/verificar-ci-local.sh`, `tools/verificar-restauracion-otra-instancia.sh`.
5. Reproducir las mediciones de sesión con `bash tools/mediciones/medir-final.sh` (requiere `sqlcmd` y la base cargada).

Cuentas de demostración: `ana`, `luis`, `maria`, `sofia`, `admin` (claves PBKDF2 en `UsuariosApp`, independientes de los logins del motor).

### 10.2 Inventario

| Archivo | Aporte |
| --- | --- |
| `app/Program.cs` | Endpoints, autenticación, sesión, TLS, CSRF, XMLDSig |
| `app/sql/01`–`18` | Modelo de seguridad completo |
| `app/wwwroot/` | Consola: pantallas por rol |
| `pki/` | CA raíz, certificado de firma y CMK |
| `tools/` | `AeSetup`, verificaciones de restauración y CI, y el arnés de medición |
| `tests/` | 24 pruebas xUnit |
| `README.md` | Puesta en marcha, mapa control → archivo y límites |
| `DESARROLLO.md` | Historia del desarrollo, mediciones y decisiones |
| `MATRIZ-DE-PROTECCION.md` | Sujetos × objetos, ACL y capacidades |
| `COMPARACION-CIFRADO.md` | Las cuatro estrategias frente a frente |

### 10.3 Fuentes internas

Este informe se apoya en los documentos del repositorio (`README.md`, `MATRIZ-DE-PROTECCION.md`, `COMPARACION-CIFRADO.md`, `DESARROLLO.md`), en los scripts `app/sql` y en las mediciones registradas durante el desarrollo. Las cifras de rendimiento provienen de un arnés sobre 20.000 sesiones sintéticas, con respaldo y restauración de las sesiones reales antes y después de cada corrida; el arnés está versionado en `tools/mediciones/`.
