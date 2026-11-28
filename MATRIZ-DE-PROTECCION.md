# Matriz de protección — Banco Andino

Documento de la **Fase 1** (Unidad 1, §1.8: dominios de protección y matrices de acceso). Formaliza la pregunta *¿quién puede hacer qué sobre qué recurso?* en la base `BancoAndino`, deriva la respuesta a sus dos representaciones —**ACL** (por objeto) y **lista de capacidades** (por sujeto)— y la contrasta con lo que el motor tiene configurado hoy.

La matriz es una **fotografía** del estado de protección (Lampson, §1.8.2): si cambia un `GRANT`, una máscara o un rol, este documento debe actualizarse. La sección 11 indica qué declaración SQL respalda cada celda para que la revisión sea mecánica.

- **Instancia:** SQL Server 2022 Developer, base `BancoAndino`.
- **Estado:** verificado el 27/11/2026 contra los scripts `app/sql/01` a `09`.
- **Alcance:** objetos de la base y del motor que protegen datos del caso. Quedan fuera la red, el sistema operativo y la alta disponibilidad (declarados fuera de alcance en el informe).

---

## 1. Sujetos (dominios)

Cada sujeto es un **principal de base** con su rol. La aplicación nunca decide por su cuenta: abre la conexión y ejecuta `EXECUTE AS USER = '<principal>'`, de modo que el veredicto (lo que se concede, lo que se enmascara y lo que se niega) lo emite SQL Server.

| Cód. | Sujeto | Principal de base | Rol | Función en el banco |
| --- | --- | --- | --- | --- |
| **C** | Cajero | `cajero_ana` | `rol_cajero` | Atención al público: consulta clientes y movimientos. |
| **S** | Supervisor | `supervisor_luis` | `rol_supervisor` | Supervisa la operación de caja; mismas lecturas que el cajero. |
| **R** | Riesgos | `riesgos_maria` | `rol_riesgos` | Analiza fraude y riesgo crediticio; único con datos reales y descifrado. |
| **A** | Auditor | `auditor_sofia` | `rol_auditor` | Auditoría interna: lee todo, no opera ni administra. |
| **D** | DBA | `dba_admin` | `db_owner` | Administra el esquema, las máscaras, los permisos y las claves. |
| **PA** | Proceso de la aplicación | conexión `sysadmin` | — | Autentica, firma transacciones y cifra tarjetas; suplanta a los anteriores. |

**Derecho *switch* (dominios como objetos, §1.8.4).** `PA` no necesita leer las tablas: necesita **cambiar de dominio** hacia `C`, `S`, `R`, `A` y `D` (`IMPERSONATE`) para que cada consulta se ejecute con los derechos del usuario. Es el derecho `switch` del modelo y se analiza en la sección 10.

---

## 2. Objetos protegidos

| Cód. | Objeto | Contenido sensible | Riesgo principal |
| --- | --- | --- | --- |
| **CL** | `dbo.Clientes` | CI, nombre, email, teléfono, tarjeta, saldo | Fuga de PII y de datos de tarjeta. |
| **TX** | `dbo.Transacciones` | Montos, fechas, cuenta origen y destino | Alteración o repudio de operaciones. |
| **EM** | `dbo.Empleados` | CI, cargo, salario, email corporativo | Divulgación de salarios entre áreas. |
| **UA** | `dbo.UsuariosApp` | Usuario, sal + hash, rol, estado de bloqueo | Suplantación de cuentas de la consola. |
| **TC** | `dbo.TarjetasCifradas` | Número y CVV cifrados con AES-256; últimos 4 visibles | Descifrado no autorizado del dato completo. |
| **TF** | `dbo.TransaccionesFirmadas` | XML, hash SHA-256, firma RSA | Alteración de documentos sin detectar el cambio. |
| **RA** | Registro de auditoría (`Audit_BancoAndino`) | Accesos y operaciones sobre las tablas sensibles | Borrado de huellas por un privilegiado. |
| **KC** | Claves y certificados | DMK, `CertBancoAndino` (TDE), `CertTransacciones`, `CertColumnas`, `SK_Tarjetas` | Uso indebido o pérdida de la jerarquía criptográfica. |
| **MS** | Metadatos de seguridad | `sys.masked_columns`, `sys.database_permissions`, roles | Cambio silencioso de la política de acceso. |

---

## 3. Derechos y convenciones

Definición de la guía del Laboratorio 1.1, aplicada a objetos de base de datos:

| Abrev. | Derecho | Significado | Equivalente en SQL Server |
| --- | --- | --- | --- |
| **L** | Lectura | Ver o consultar el contenido sin modificarlo. | `SELECT` |
| **E** | Escritura | Crear o modificar el contenido. | `INSERT`, `UPDATE` |
| **X** | Ejecución | Ejecutar la operación que el objeto representa. | `EXECUTE` sobre procedimientos |
| **B** | Borrado | Eliminar el objeto o su contenido. | `DELETE`, `DROP` |
| **C** | Control | Modificar los derechos de otros sujetos sobre ese objeto. | `CONTROL`, `ALTER`, `GRANT`/`DENY`/`REVOKE` |
| **—** | Sin acceso | El sujeto no tiene ningún derecho sobre ese objeto. | Sin `GRANT` (o `DENY` explícito) |

Convenciones de las tablas siguientes:

- `L*` — lectura **enmascarada** por DDM: el sujeto ve el dato, pero no el valor real.
- `X(d)` — ejecutar el **descifrado** de tarjeta; `X(g)` — **guardar/cifrar**; `X(f)` — **firmar**; `X(a)` — **alterar/restaurar** un documento firmado.
- `†` — derecho **efectivo a través de la consola**, verificado por la aplicación y no por el motor (la conexión consulta como `dbo`/`sysadmin`).
- `C` en la fila del DBA significa **control sin lectura** del contenido: es el punto de diseño central de este documento.

---

## 4. Reglas de negocio modeladas

1. **Cajero:** lee clientes y transacciones para atender al público; **no** accede a empleados ni a usuarios de la aplicación.
2. **Supervisor:** las mismas lecturas que el cajero; tampoco accede a empleados.
3. **Riesgos:** lee todo y ve los **valores reales** (`UNMASK`); descifra tarjeta y CVV porque administra la clave.
4. **Auditor:** lee todo **enmascarado**, incluida la bitácora; no descifra, no modifica y no administra.
5. **DBA:** administra estructura, máscaras, permisos y claves, pero **no lee el contenido** de los datos de negocio (separación de funciones).
6. **Proceso de la aplicación:** autentica, firma y cifra; **no** consulta datos de negocio por su cuenta, sino que suplanta al usuario de base.
7. **Auditoría:** ningún sujeto humano escribe ni borra el registro; lo escribe el motor y nadie puede editarlo.
8. **Escrituras de negocio:** ningún sujeto tiene `E` ni `B` directo sobre `Clientes`, `Transacciones` o `Empleados`; las altas de tarjetas y la firma pasan por procedimientos (`X`), no por `INSERT`/`UPDATE` de tabla.

---

## 5. Matriz implementada (estado actual del motor)

Lo que SQL Server concede **hoy**, tal como queda configurado por `01_esquema.sql`, `05_firma_transacciones.sql` y `06_cifrado_columnas.sql`.

| Sujeto | CL | TX | EM | UA | TC | TF | RA | KC | MS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **C** Cajero | `L*` | `L` | `L* (sin Salario)` | `—` | `L, X(d)` | `L` | `—` | `—` | `—` |
| **S** Supervisor | `L* (sin NumeroTarjeta)` | `L` | `—` | `—` | `L, X(d)` | `L` | `—` | `—` | `—` |
| **R** Riesgos | `L` | `L` | `L` | `—` | `L, X(d)` | `L` | `—` | `C` | `—` |
| **A** Auditor | `L*` | `L` | `L*` | `—` | `L, X(d)` | `L` | `L†` | `—` | `—` |
| **D** DBA | `—` | `—` | `—` | `—` | `—` | `X(a)` | `—` | `—` | `L` |
| **PA** Aplicación | `—` | `—` | `—` | `L,E` | `X(g)` | `L, X(f)` | `L†` | `—` | `L` |

**Lectura de la tabla.** Las seis filas están acotadas: ninguna tiene `E` ni `B` sobre datos de negocio. `D` conserva solo `VIEW DEFINITION` (`MS L`) y `EXECUTE` sobre alterar/restaurar; no lee datos ni abre claves. `PA` no lee `CL`, `TX` ni `EM`: suplanta al usuario y el motor decide. La auditoría se lee con un procedimiento firmado (`†`), no con `SELECT` directo sobre el archivo.

Las secciones 6 a 10 conservan el diseño y su justificación; la 11 contrasta celda por celda y la 16 registra el cierre de brechas.

---

## 6. Matriz objetivo (mínimo privilegio)

Diseño al que debe converger la implementación. Las celdas de **D** y **PA** son las que cambian respecto de la sección 5.

| Sujeto | CL | TX | EM | UA | TC | TF | RA | KC | MS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **C** Cajero | `L*` | `L` | `L* (sin Salario)` | `—` | `L, X(d)` | `L` | `—` | `—` | `—` |
| **S** Supervisor | `L* (sin NumeroTarjeta)` | `L` | `—` | `—` | `L, X(d)` | `L` | `—` | `—` | `—` |
| **R** Riesgos | `L` | `L` | `L` | `—` | `L, X(d)` | `L` | `—` | `C` | `—` |
| **A** Auditor | `L*` | `L` | `L*` | `—` | `L, X(d)` | `L` | `L` | `—` | `L` |
| **D** DBA | `—` | `—` | `—` | `—` | `—` | `X(a)` | `—` | `—` | `L` |
| **PA** Aplicación | `—` | `—` | `—` | `L, E` | `X(g)` | `L, X(f)` | `L†` | `—` | `L` |

**Ajuste tras el cierre:** el diseño inicial daba a `D` `C` sobre los datos y a `PA` `X` sobre la auditoría; la implementación quedó **más restrictiva**: `D` administra por procedimientos (`EXECUTE`) y no recibe `CONTROL`; `PA` lee la auditoría con `EXECUTE` sobre `usp_LeerAuditoria` (`L†`). `D` no tiene `X(d)` ni `CONTROL` sobre `SK_Tarjetas`.

**Derecho *switch*:** `PA` conserva `IMPERSONATE` sobre los cinco usuarios de base (no se modela como columna para no duplicar las filas). Es el único derecho que necesita para que el motor aplique la fila del sujeto suplantado.

---

## 7. Justificación celda por celda

Se justifican las celdas no vacías de la **matriz objetivo**. Cada una responde por qué el derecho es necesario y por qué no se otorgó uno mayor.

### Cajero (C)

- **CL `L*`** — Atiende consultas y reclamos: necesita identificar al cliente y ver su saldo, pero no la tarjeta completa ni el contacto real. El `SELECT` es sobre la tabla; las máscaras de `01_esquema.sql` §2 hacen el resto. Se lee **enmascarado**, no se le niega la lectura: sin `L` no podría atender.
- **TX `L`** — Consulta movimientos para responder por una operación; no los registra. La caja de este caso no concilia, así que `E` no tiene justificación.
- **EM `L* (sin Salario)`** — Necesita identificar al empleado que atiende un trámite (nombre, cargo, contacto), pero no su sueldo. El `GRANT` es por columna sobre las cinco columnas de atención y el `DENY` por columna sobre `Salario`; ese `DENY` sobrevive a un `GRANT` de tabla futuro.
- **UA `—`** — No administra cuentas de la consola.
- **TC `L, X(d)`** — Ve los últimos 4 dígitos y el criptograma; ejecuta `usp_DescifrarTarjeta` porque la consola se lo ofrece, pero el motor le niega abrir `SK_Tarjetas`. `X` sobre la operación **no** otorga derecho sobre la clave.
- **TF `L`** — Verifica firma e integridad de una transacción; no la altera ni la restaura.
- **RA, KC, MS `—`** — No lee la bitácora, no abre claves y no administra metadatos.

### Supervisor (S)

- **CL `L* (sin NumeroTarjeta)`, TX `L`, TC `L, X(d)`, TF `L`** — Las mismas necesidades operativas que el cajero: supervisa la caja, no la reemplaza. No se le agregó ningún derecho por jerarquía. La columna de tarjeta se le niega por columna: no la ve ni enmascarada.
- **EM `—` (sin GRANT)** — No hay `DENY`: la ausencia de permiso ya deniega. Se modela distinto al cajero a propósito, para mostrar que `DENY` y “sin permiso” producen el mismo efecto hoy, pero `DENY` es explícito y sobrevive a un `GRANT` futuro.
- **UA, RA, KC, MS `—`** — Igual que el cajero.

### Riesgos (R)

- **CL `L`** — Único rol con `UNMASK`: investiga fraude y riesgo crediticio y necesita el valor real. La máscara no se le aplica por decisión de negocio, no por un privilegio técnico.
- **TX `L`** — Analiza patrones de fraude sobre los movimientos.
- **EM `L`** — El análisis de riesgo operativo incluye la nómina; sin `UNMASK` vería el salario enmascarado y el análisis no serviría.
- **TC `L, X(d)`** — Descifra tarjeta y CVV para una investigación concreta. La lectura sola no alcanza: el descifrado es una operación aparte.
- **TF `L`** — Verifica que el documento no haya sido alterado.
- **KC `C`** — `CONTROL` sobre `CertColumnas` y `SK_Tarjetas` es lo que **realmente** permite descifrar. Es el único sujeto con ese control; sin él, `X(d)` falla.
- **UA, RA, MS `—`** — No administra cuentas ni la bitácora.

### Auditor (A)

- **CL `L*`, EM `L*`, TX `L`** — Audita sin necesidad de ver PII real: el enmascaramiento alcanza para comprobar que el control existe y que la máscara está aplicada.
- **TC `L, X(d)`** — Comprueba que el descifrado está denegado para los roles operativos; su propio `X` falla igual porque no tiene `C` sobre la clave. Es una prueba negativa, no una necesidad de negocio.
- **TF `L`** — Revisa firmas e integridad sin poder alterar ni restaurar.
- **RA `L`** — Lee la bitácora para auditar accesos; no la modifica ni la borra.
- **MS `L`** — Revisa la ACL y las máscaras vigentes (objetivo; hoy no hay pantalla para el auditor).
- **UA, KC `—`** — No administra cuentas ni claves.

### DBA (D)

- **CL, TX, EM, TC, KC, RA `—`** — No lee datos ni abre claves. Administra máscaras y permisos con `usp_AdminPermiso`/`usp_AdminMascara`, que corren como `dbo` (`EXECUTE AS OWNER`): el DBA tiene `EXECUTE`, no `CONTROL`.
- **TF `X(a)`** — Ejecuta alterar/restaurar, que existen solo para demostrar la detección de integridad.
- **UA `—`** — La consola gestiona las cuentas con el login de aplicación; el DBA autoriza la operación por rol, pero no recibe `SELECT`/`UPDATE` directo sobre `UsuariosApp`.
- **MS `L`** — `VIEW DEFINITION` le permite ver la definición de los objetos y la ACL, sin leer su contenido.

### Proceso de la aplicación (PA)

- **UA `L, E`** — Autentica (lee el hash y el estado) y actualiza intentos fallidos y bloqueo.
- **TC `X(g)`** — Cifra al guardar una tarjeta. **No** tiene `X(d)`: el descifrado se ejecuta en el contexto del usuario, para que el motor aplique su permiso y no el de la aplicación.
- **TF `X(f)`** — Firma en el contexto de la aplicación.
- **MS `L`** — Lee el catálogo para el panel de administración.
- **CL, TX, EM `—`** — No consulta datos de negocio por su cuenta: suplanta al usuario de base, que es quien tiene el permiso. Este `—` es lo que hace que la consola no pueda “saltarse” la matriz.
- **RA `L†`** — Ejecuta `usp_LeerAuditoria`, firmado por `CertAuditoria`; no tiene `SELECT` sobre el archivo.
- **KC `—`** — Las claves las abren los procedimientos dentro de su propio contexto (*ownership chaining*).

---

## 8. Mínimo privilegio: derechos que se negaron a propósito

Casos del diseño en los que un derecho “razonable a primera vista” se negó, con el daño que habilitaría:

1. **Cajero sin `Salario` y supervisor sin `NumeroTarjeta`.** El cajero necesita identificar al empleado, no conocer su sueldo; el supervisor necesita el resto del cliente, no el plástico. Un `GRANT` de tabla no reabre esas columnas: el `DENY` por columna prevalece.
2. **Cajero y supervisor con `X(d)` pero sin `C` sobre la clave.** Procesar un pago requiere ver la tarjeta, pero no el número completo: con los últimos 4 alcanza para identificar el plástico. Si tuvieran `CONTROL` sobre `SK_Tarjetas`, podrían descifrar toda la base de tarjetas, no solo la que están atendiendo.
3. **Auditor sin `UNMASK`.** Auditar no exige ver el dato real; con la máscara alcanza para verificar que el control se aplica. Si tuviera `UNMASK`, la auditoría se convertiría en una vía de fuga de PII.
4. **DBA sin `L` ni `C` sobre Clientes, Transacciones y Empleados.** Es el caso más incómodo y el más importante: administrar permisos no requiere leer el contenido. Si conservara `db_owner`, podría leer todo y la separación de funciones desaparecería.
5. **Nadie con `E` ni `B` sobre la auditoría.** Si el DBA pudiera escribir o borrar el registro, podría ocultar sus propias acciones y la auditoría perdería valor probatorio.
6. **`PA` sin `L` sobre datos de negocio.** Si la aplicación leyera las tablas con su propia cuenta, el `EXECUTE AS USER` sería decorativo: el motor nunca evaluaría los permisos del usuario.
7. **Nadie con `E` sobre tablas de negocio.** Las escrituras pasan por `usp_GuardarTarjeta` y `usp_FirmarTransaccion`; no hay `INSERT`/`UPDATE` directo sobre `Clientes`, `Transacciones` ni `Empleados`. El derecho es sobre la operación (`X`), no sobre la tabla.

---

## 9. Derivación 1 — ACL (organizada por objeto)

La misma matriz, guardada “por columnas”. Es la forma en que SQL Server la almacena realmente en `sys.database_permissions`.

- **CL — Clientes:** Cajero (`L*`), Supervisor (`L*`, sin `NumeroTarjeta`), Riesgos (`L`), Auditor (`L*`). DBA y `PA` sin acceso.
- **TX — Transacciones:** Cajero (`L`), Supervisor (`L`), Riesgos (`L`), Auditor (`L`). DBA y `PA` sin acceso.
- **EM — Empleados:** Cajero (`L*`, sin `Salario`), Riesgos (`L`), Auditor (`L*`). Supervisor, DBA y `PA` sin acceso.
- **UA — UsuariosApp:** `PA` (`L, E`). Ningún rol de negocio ni el DBA tienen acceso directo.
- **TC — TarjetasCifradas:** Cajero (`L, X(d)`), Supervisor (`L, X(d)`), Riesgos (`L, X(d)`), Auditor (`L, X(d)`), `PA` (`X(g)`). DBA sin acceso.
- **TF — TransaccionesFirmadas:** Cajero (`L`), Supervisor (`L`), Riesgos (`L`), Auditor (`L`), DBA (`X(a)`), `PA` (`L, X(f)`).
- **RA — Registro de auditoría:** Auditor y DBA leen por `usp_LeerAuditoria` (`L†`), firmado por `CertAuditoria`. **Ningún sujeto tiene `E` ni `B` directo.**
- **KC — Claves y certificados:** Riesgos (`C`). La app tiene `CONTROL` solo sobre el certificado TDE para respaldarlo; el DBA no abre claves.
- **MS — Metadatos de seguridad:** DBA (`L`), `PA` (`L`) y Auditor (`L` desde `18_metadatos.sql`, B5 cerrada). El auditor lee la ACL y las máscaras, no los datos en claro ni la definición de los procedimientos de administración.

**Ventaja concreta en este proyecto:** para responder *“¿quién puede leer Empleados?”* o revocar el acceso de un cajero a una tabla, la ACL es una sola lista y un solo `REVOKE`. Es lo que hace `01_esquema.sql` §4.

---

## 10. Derivación 2 — Lista de capacidades (organizada por sujeto)

La misma matriz, guardada “por filas”. Es lo que la consola muestra en `/api/sesion`, que deriva los permisos efectivos con `fn_my_permissions` dentro del contexto del usuario.

- **Cajero:** `{CL: L*}`, `{TX: L}`, `{EM: L*, sin Salario}`, `{TC: L, X(d)}`, `{TF: L}`.
- **Supervisor:** `{CL: L*, sin NumeroTarjeta}`, `{TX: L}`, `{TC: L, X(d)}`, `{TF: L}`.
- **Riesgos:** `{CL: L}`, `{TX: L}`, `{EM: L}`, `{TC: L, X(d)}`, `{TF: L}`, `{KC: C}`.
- **Auditor:** `{CL: L*}`, `{TX: L}`, `{EM: L*}`, `{TC: L, X(d)}`, `{TF: L}`, `{RA: L}`, `{MS: L}`.
- **DBA:** `{TF: X(a)}`, `{MS: L}`; sin `L`, `C`, `E` ni `B` sobre datos, claves o auditoría directa.
- **PA:** `{UA: L, E}`, `{TC: X(g)}`, `{TF: L, X(f)}`, `{RA: L†}`, `{MS: L}` + `switch` (`IMPERSONATE`) sobre `C`, `S`, `R`, `A`, `D`.

**Ventaja concreta en este proyecto:** para dar de baja a un auditor o responder *“¿a qué accede esta persona?”*, la lista de capacidades se lee de una vez; en la consola es exactamente la pantalla de sesión. **Desventaja:** revocar un derecho suelto exige recorrer la lista del sujeto; en SQL Server se resuelve con roles, que son capacidades colectivas, y por eso la revocación real se hace sobre el rol (ACL) y no sobre la persona.

---

## 11. Coherencia con la implementación

Qué hay en el motor para cada celda de la matriz objetivo. **Estado:** ✅ implementado · ⚠️ implementado con más privilegio · 🟡 aplicado por la aplicación, no por el motor · ❌ no implementado.

| Celda | Declaración / mecanismo real | Estado |
| --- | --- | --- |
| C, A → CL `L*` | `GRANT SELECT ON dbo.Clientes` + 5 máscaras (`01` §2 y §4) | ✅ |
| S → CL `L*` sin `NumeroTarjeta` | `GRANT SELECT (ClienteID, Nombre, CI, Email, Telefono, SaldoCuenta)` + `DENY SELECT (NumeroTarjeta)` | ✅ |
| R → CL `L` | `GRANT UNMASK TO rol_riesgos` | ✅ |
| C → EM `L*` sin `Salario` | `GRANT SELECT (EmpleadoID, Nombre, CI, Cargo, EmailCorporativo)` + `DENY SELECT (Salario)` | ✅ |
| S → EM `—` | Sin `GRANT` a `rol_supervisor` | ✅ |
| R, A → EM `L` / `L*` | `GRANT SELECT` + máscaras; `A` sin `UNMASK` | ✅ |
| C, S, R, A → TX `L` | `GRANT SELECT ON dbo.Transacciones` | ✅ |
| C, S, R, A → TC `L` | `GRANT SELECT ON dbo.TarjetasCifradas` | ✅ |
| C, S, R, A → TC `X(d)` | `GRANT EXECUTE ON usp_DescifrarTarjeta`; solo `R` abre la clave | ✅ |
| R → KC `C` | `CONTROL` sobre `CertColumnas` y `SK_Tarjetas` | ✅ |
| C, S, R, A → TF `L` | `GRANT SELECT` sobre la tabla y la vista | ✅ |
| A, D → RA `L†` | `EXECUTE` sobre `usp_LeerAuditoria`, firmado por `CertAuditoria` | ✅ |
| D → TF `X(a)` | `GRANT EXECUTE` a `dba_admin` sobre alterar/restaurar | ✅ |
| D → CL, TX, EM `—` | Sin `db_owner`; solo `VIEW DEFINITION` | ✅ |
| D → TC, KC `—` | Sin `CONTROL` sobre clave/certificado; *fallback* eliminado | ✅ |
| PA → UA `L, E` | `GRANT SELECT, UPDATE ON dbo.UsuariosApp` | ✅ |
| PA → TC `X(g)`, TF `X(f)` | `GRANT EXECUTE` en `usp_GuardarTarjeta`/`usp_FirmarTransaccion`; `SELECT` en firmas | ✅ |
| PA → *switch* | `IMPERSONATE` sobre los cinco usuarios | ✅ |
| A → MS `L` | `GRANT VIEW DEFINITION TO rol_auditor` (`18_metadatos.sql`) y `/api/metadatos` en su contexto | ✅ |

Todas las filas coinciden con el motor: el auditor lee la ACL, las máscaras y el inventario de columnas con `VIEW DEFINITION`, pero no tiene `CONTROL` (no puede cambiar nada), ni `UNMASK`, ni acceso a `ClientesAE`.

---

## 12. Brechas y plan de cierre

| # | Brecha | Por qué importa | Cierre propuesto |
| --- | --- | --- | --- |
| **B1** | `dba_admin` es `db_owner`: `L,E,X,B,C` sobre todo e ignora DDM. | Un DBA comprometido lee toda la PII; la separación `C`/`L` es ficticia. | Quitar `db_owner`. Otorgar permisos granulares (`ALTER ANY MASK`, `ALTER ANY USER`, `VIEW DEFINITION`, control del certificado TDE) y mover los `GRANT`/`DENY` a procedimientos **firmados por certificado**: en SQL Server, quien otorga un `SELECT` necesita `GRANT OPTION` o `CONTROL`, y ambos permiten leer. El procedimiento firmado ejecuta el cambio con los derechos del certificado y el DBA solo tiene `X`. |
| **B2** | La conexión de la aplicación es `sysadmin`. | Si esa cuenta se compromete, la matriz completa es cosmética. | Login `app_bancoandino` sin roles fijos: `IMPERSONATE` sobre los cinco usuarios, `EXECUTE` en `usp_FirmarTransaccion` y `usp_GuardarTarjeta`, `SELECT, UPDATE` en `UsuariosApp`, `SELECT` en catálogo. Nada de `db_owner` ni `sysadmin`. |
| **B3** | Auditoría, alterar/restaurar y administración se autorizan en `Program.cs`, no en el motor. | El control no viaja con la base: otro cliente SQL con la misma conexión lo saltea. | `GRANT EXECUTE` a roles sobre procedimientos firmados (`usp_LeerAuditoria`, `usp_AlterarTransaccion` solo a un rol de demostración) y `VIEW DEFINITION` para metadatos. La comprobación en la app queda como defensa en profundidad, no como única barrera. |
| **B4** | *Fallback* de `dba` al descifrar (`/api/columnas/descifrar`). | Es una puerta trasera del endpoint: convierte una denegación del motor en una lectura exitosa. | Eliminarlo. Si se necesita la demostración, hacerla con una sesión `sysadmin` explícita y separada, nunca dentro del mismo endpoint que usa el cajero. |
| **B5** | El auditor no ve metadatos (`MS`). | No puede verificar la ACL que audita. | **Cerrada:** `VIEW DEFINITION` a `rol_auditor` y endpoint `/api/metadatos` que consulta `sys.database_permissions`, `sys.masked_columns`, `sys.columns` y los roles en el contexto del auditor. |
| **B6** | `CHECK_POLICY = OFF` y sal estática + SHA-256 en `UsuariosApp`. | La política de contraseñas del curso no se aplica y el hash es vulnerable a tablas precalculadas. | `CHECK_POLICY = ON`, `PASSWORD_EXPIRY`, sal aleatoria por usuario y PBKDF2/Argon2 en la aplicación. |

**Estado (noviembre de 2026).** B1, B2, B4, B5 y B6 están cerradas. B3 quedó cerrada para la auditoría (procedimiento firmado) y la administración (procedimientos con `EXECUTE AS OWNER`); la comprobación de rol en `Program.cs` queda como defensa en profundidad. B5 se cerró en `18_metadatos.sql` y en la pantalla *Metadatos y ACL*: el auditor ve la ACL y las máscaras sin obtener `CONTROL` ni `UNMASK`.

---

## 13. Cómo verificar la matriz

Las consultas se ejecutan como `sysadmin` y reproducen lo que hace la consola (`ConsultaComoAsync`):

```sql
USE BancoAndino;

-- ACL real: quién tiene qué sobre qué
SELECT dp.name AS sujeto, p.permission_name AS permiso, p.state_desc AS estado,
       ISNULL(OBJECT_NAME(p.major_id), '(base de datos)') AS objeto
FROM sys.database_permissions p
JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
WHERE dp.name LIKE 'rol_%' OR dp.name IN ('cajero_ana','supervisor_luis','riesgos_maria','auditor_sofia','dba_admin')
ORDER BY sujeto, objeto, permiso;

-- Capacidades efectivas de un sujeto (lo que muestra /api/sesion)
EXECUTE AS USER = 'cajero_ana';
SELECT USER_NAME() AS principal;
SELECT * FROM fn_my_permissions('dbo.Clientes', 'OBJECT');
SELECT * FROM fn_my_permissions('dbo.Empleados', 'OBJECT');  -- vacío: DENY
SELECT * FROM dbo.Empleados;                                 -- Msg 229
REVERT;
```

Comprobaciones que ya corren en `tests/BancoAndino.Tests/ApiTests.cs`:

- `Cajero_ve_los_datos_pero_no_puede_descifrar_la_tarjeta` — `X(d)` sin `C` sobre la clave.
- `Cajero_lee_empleados_pero_no_la_columna_salario` — `DENY` por columna, error 230.
- `Supervisor_no_puede_leer_la_columna_numero_tarjeta` — `DENY` por columna y 403 en `Empleados`.
- `Riesgos_puede_descifrar_la_tarjeta` — `C` sobre `SK_Tarjetas`.
- `La_cuenta_de_aplicacion_no_es_sysadmin_ni_db_owner` y `El_dba_no_lee_datos_por_su_cuenta` — B1 y B2.
- `La_auditoria_registra_accesos_denegados` — lectura por el procedimiento firmado y `succeeded = 0`.
- `Inferencia_por_umbral_revela_el_saldo_real` — DDM protege la salida, no el predicado.
- `La_demo_de_sqli_muestra_la_diferencia` — concatenación vs. parámetro.
- `La_firma_xmldsig_es_valida` — firma XML embebida, no solo un hash.
- `La_cookie_de_sesion_es_httponly_y_autentica`, `El_logout_invalida_el_token` — sesión y revocación.
- `La_base_esta_cifrada_con_TDE` y `Las_transacciones_firmadas_informan_firma_e_integridad` — objetos `KC` y `TF`.

---

## 14. Preguntas de reflexión (adaptadas del Laboratorio 1.1)

**1. ¿Qué situación de esta matriz es más sencilla de auditar con ACL y cuál con capacidades?**
Con ACL, *“¿quién puede leer Empleados?”*: una sola lista y un `DENY` visible. Con capacidades, la baja de un auditor: se lee su lista completa y se revoca todo de una vez, en lugar de recorrer las nueve ACL. En la consola, `/api/admin/estado` muestra la ACL y `/api/sesion` muestra las capacidades: son las dos vistas del mismo estado.

**2. La regla que separa `C` de `L` para el DBA, ¿qué principio refleja?**
Mínimo privilegio y separación de funciones: administrar permisos no requiere leer el contenido. Es exactamente lo que `db_owner` rompe y lo que B1 corrige.

**3. Si por error el cajero recibiera `E` sobre `Clientes`, ¿qué daño habilitaría?**
Podría modificar `SaldoCuenta` para inflar un saldo o cambiar `NumeroTarjeta` para desviar una transferencia; con `B` sobre `Transacciones`, borrar el rastro de la operación. Hoy no tiene ni `E` ni `B`: solo `L*`.

**4. ¿Qué diferencia hay entre el registro de auditoría y los demás objetos?**
Es el único sin `E` ni `B` para ningún sujeto: lo escribe el motor. Si el DBA pudiera editarlo, podría borrar sus propias huellas y el registro perdería valor probatorio. Hoy se lee con `usp_LeerAuditoria`, firmado por `CertAuditoria` (que sí tiene `CONTROL SERVER`); la app solo recibe `EXECUTE`, y el procedimiento es un objeto de alto valor que debe auditarse.

---

## 15. Trazabilidad

| Archivo | Qué aporta a la matriz |
| --- | --- |
| `app/sql/01_esquema.sql` | Tablas (`CL`, `TX`, `EM`), máscaras (§2), logins y roles (§3), permisos y `DENY` (§4). |
| `app/sql/03_usuarios_app.sql` | `UA`: cuentas, sal + hash y principal de base de cada una. |
| `app/sql/09_bloqueo_intentos.sql` | Columnas de bloqueo de `UA` (intentos, vencimiento). |
| `app/sql/04_tde.sql` | `KC`: DMK, certificado TDE y respaldo. |
| `app/sql/05_firma_transacciones.sql` | `TF`: documentos, firma, vista de integridad y permisos de lectura (§7). |
| `app/sql/06_cifrado_columnas.sql` | `TC` y `KC`: clave AES-256, procedimientos y `CONTROL` de la clave. |
| `app/sql/02_auditoria.sql` + `14_auditoria_lector.sql` + `15_auditoria_objetos.sql` | `RA`: server audit, lector firmado y objetos auditados. |
| `app/sql/10_demo_sqli.sql` | Demostración de concatenación vs. parámetro (B3 en la capa de datos). |
| `app/sql/11_comparacion_cifrado.sql` + `COMPARACION-CIFRADO.md` | Comparación TDE / columna / frase de paso / Always Encrypted. |
| `app/sql/12_restauracion_prueba.sql` | Restauración verificada: `ENCRYPTED`, `DBCC CHECKDB`, conteos y firmas. |
| `app/sql/13_admin_procs.sql` | Administración con `EXECUTE AS OWNER`: `D` sin `CONTROL` (B1). |
| `app/sql/16_always_encrypted.sql` | Tabla `ClientesAE` con CEK y permisos; SQL dinámico para poder ejecutarse sin CEK. |
| `app/sql/17_sesiones.sql` | `dbo.SesionesApp` y procedimientos de alta, validación, cierre y revocación global. |
| `app/sql/18_metadatos.sql` | `VIEW DEFINITION` para `rol_auditor` y verificación en su contexto (B5). |
| `pki/crear-pki.ps1` + `pki/crear-cmk.ps1` | CA raíz y certificado de firma XMLDSig; certificado CMK de Always Encrypted. |
| `tools/AeSetup` | Genera la CEK, registra CMK/CEK y siembra `ClientesAE` con el driver. |
| `tools/verificar-restauracion-otra-instancia.sh` | Restauración verificada en un contenedor limpio con SMK propia. |
| `tools/verificar-ci-local.sh` | Réplica local del workflow de CI sobre un contenedor limpio. |
| `app/Program.cs` | `PA`, `IMPERSONATE`, PBKDF2, cookie `HttpOnly`, TLS, CSRF, XMLDSig con cadena de CA y los controles de rol como defensa en profundidad. |
| `app/wwwroot/app.js` | Menú filtrado por rol, inferencia DDM, SQLi, auditoría con denegados, metadatos, Always Encrypted y XMLDSig. |
| `tests/BancoAndino.Tests/ApiTests.cs` + `LimitacionesTests.cs` | 24 pruebas de la matriz, sesión persistente, metadatos, Always Encrypted, auditoría y demostraciones. |

**Mantenimiento:** todo cambio de permiso, máscara o rol debe actualizar la sección 5 y la fila correspondiente de la sección 11 en el mismo commit. Si el cambio altera el diseño, se actualiza también la sección 6.

---

## 16. Cierre de brechas (noviembre de 2026)

| Brecha | Estado | Evidencia |
| --- | --- | --- |
| **B1** — DBA con `db_owner` | **Cerrada** | `dba_admin` sin `db_owner`; solo `VIEW DEFINITION` y `EXECUTE` sobre `usp_AdminPermiso`, `usp_AdminMascara`, `usp_AlterarTransaccion` y `usp_RestaurarTransaccion`. `El_dba_no_lee_datos_por_su_cuenta` devuelve `403`. |
| **B2** — conexión `sysadmin` | **Cerrada** | Login `app_bancoandino` sin roles fijos, con `IMPERSONATE`, `SELECT, UPDATE` en `UsuariosApp`, `EXECUTE` acotado y `CONTROL` solo sobre el certificado TDE. `La_cuenta_de_aplicacion_no_es_sysadmin_ni_db_owner` lo comprueba. |
| **B3** — controles solo en la app | **Cerrada para auditoría y administración** | `usp_LeerAuditoria` firmado por `CertAuditoria`; `usp_Admin*` con `EXECUTE AS OWNER`. Los chequeos de rol de `Program.cs` quedan como defensa en profundidad, no como única barrera. |
| **B4** — *fallback* del DBA al descifrar | **Cerrada** | El endpoint ya no reintenta como dueño; el cajero recibe `403` y `numero = null`. |
| **B5** — auditor sin metadatos | **Cerrada** | `GRANT VIEW DEFINITION TO rol_auditor` (`18_metadatos.sql`) y `/api/metadatos`; `El_auditor_lee_la_acl_y_las_mascaras_sin_poder_cambiarlas` comprueba `view_definition = 1`, `control = 0` y que el cajero recibe `403`. |
| **B6** — `CHECK_POLICY = OFF` y SHA-256 con sal fija | **Cerrada** | `CHECK_POLICY = ON`, PBKDF2-HMAC-SHA256 con 210.000 iteraciones y sal aleatoria de 16 bytes; rotación en `08`. |

La matriz implementada (§5) es la que el motor concede hoy; §6 conserva la intención del diseño y §11 contrasta cada celda. No queda ninguna brecha de privilegios abierta: B1–B6 están cerradas y cubiertas por pruebas.

### Otras limitaciones cerradas

| Limitación | Estado | Evidencia |
| --- | --- | --- |
| Always Encrypted solo documentado | **Cerrada** | CMK en `CurrentUser\My`, CEK cifrada con RSA-OAEP, `dbo.ClientesAE` con columnas deterministas y aleatorias, pantalla con texto claro vs. binario. `Always_encrypted_guarda_binario_y_descifra_solo_en_el_cliente`. |
| Sesiones en memoria del proceso | **Cerrada** | `dbo.SesionesApp` guarda el SHA-256 del token; caducidad deslizante/absoluta y revocación las aplica el motor. `La_sesion_sobrevive_a_otro_proceso_de_la_aplicacion`, `La_revocacion_global_alcanza_a_otras_sesiones_y_procesos`. |
| Certificado XMLDSig efímero | **Cerrada (CA local)** | `pki/crear-pki.ps1` emite el certificado desde una CA raíz; la app valida con `X509Chain` y `CustomRootTrust`. `La_firma_xmldsig_se_valida_contra_la_raiz_de_la_CA`. |
| Restauración solo en la misma instancia | **Cerrada** | `tools/verificar-restauracion-otra-instancia.sh`: contenedor limpio, SMK propia, certificado importado, `ENCRYPTED`, AES 256, `DBCC CHECKDB`, conteos y firmas. |
| CI sin corridas | **Validado localmente** | `tools/verificar-ci-local.sh` aplica la misma secuencia del workflow sobre un contenedor limpio y corre 24/24 pruebas. La corrida remota sigue dependiendo de la facturación de la cuenta de GitHub. |
