# Comparación de cifrado — Banco Andino

El laboratorio pide contrastar las estrategias de cifrado de SQL Server. En este proyecto están implementadas las cuatro: TDE, cifrado por columna con clave simétrica, `EncryptByPassPhrase` y **Always Encrypted** con la CMK en el almacén de certificados del cliente (`MSSQL_CERTIFICATE_STORE`).

| Dimensión | TDE (`04_tde.sql`) | Por columna con clave simétrica (`06_cifrado_columnas.sql`) | `EncryptByPassPhrase` (`11_comparacion_cifrado.sql`) | Always Encrypted (`16_always_encrypted.sql` + `tools/AeSetup`) |
| --- | --- | --- | --- | --- |
| Qué cifra | Archivos `.mdf`, `.ndf`, `.ldf` y los backups | Solo las celdas de la columna indicada (`NumeroTarjeta`, `CVV`) | Solo el valor que se le pasa, celda a celda | Columnas completas, en el cliente, celda a celda |
| Dónde vive la clave | Certificado `CertBancoAndino` en `master`, protegido por la DMK | `SK_Tarjetas`, protegida por `CertColumnas`; la DMK protege al certificado | La frase de paso: no hay clave persistente en el motor | CMK en el almacén del cliente (`CurrentUser\My`), CEK cifrada con la CMK y guardada en la base |
| Quién ve el dato en claro | El motor y cualquiera con `CONTROL SERVER` o la clave | El motor al descifrar; la app solo si tiene `CONTROL` sobre el certificado | Quien conozca la frase | Solo el cliente que abre la CMK; **el motor nunca** |
| Cambios en la aplicación | Ninguno | `OPEN SYMMETRIC KEY` y `DecryptByKey` dentro de procedimientos | Pasar la frase en cada lectura/escritura | `Column Encryption Setting=Enabled` y parámetros con el tipo exacto de la columna |
| Amenaza que cubre | Robo del `.bak` o de los archivos en disco | Robo de la tabla o del backup, sin la clave | Copia de una celda aislada sin la frase | DBA comprometido, backups, memoria del motor, `SELECT *` desde SSMS |
| Lo que **no** cubre | Un DBA con la clave; consultas normales ven todo | El DBA con `CONTROL` sobre el certificado; el dato se descifra en el servidor | Fuerza bruta sobre la frase; no hay rotación ni jerarquía | El proceso que tiene la CMK; `LIKE`/rangos sobre columnas aleatorias |
| Rotación | `ALTER DATABASE ENCRYPTION KEY ... REGENERATE` | `OPEN`/`CLOSE` y rotación de `SK_Tarjetas` | Cambiar la frase obliga a recifrar cada fila | Rotar la CEK/CMK desde el cliente (`SqlColumnEncryptionCertificateStoreProvider`) |
| Rendimiento | Bajo overhead de CPU; cifra páginas | Costo por fila y por `OPEN`/`CLOSE` | Costo por fila; la frase se procesa en cada operación | Costo de RSA en el cliente al abrir la CEK; el servidor no descifra |
| En este proyecto | Activo: `BancoAndino` y las bases restauradas en `ENCRYPTED`, AES-256 | Activo: `maria` descifra; `ana` recibe el error del motor | Activo como demostración: la frase correcta devuelve el texto, la incorrecta `NULL` | Activo: `CI` determinista y `Nombre`/`SaldoCuenta`/`NumeroTarjeta` aleatorios; `sqlcmd` solo ve `varbinary` |

## Qué se verificó

### TDE

```sql
SELECT DB_NAME(dek.database_id) AS base, dek.encryption_state_desc, dek.key_algorithm, dek.key_length
FROM sys.dm_database_encryption_keys dek;
```

Resultado en la instancia local: `BancoAndino | ENCRYPTED | AES | 256`. La restauración de prueba (`12_restauracion_prueba.sql`) conserva el estado `ENCRYPTED | AES | 256` en `BancoAndino_Restaurada`, y `tools/verificar-restauracion-otra-instancia.sh` lo comprueba además en un contenedor limpio con su propia SMK.

### Columna con clave simétrica

`usp_DescifrarTarjeta` abre `SK_Tarjetas` y devuelve número y CVV. La prueba `Riesgos_puede_descifrar_la_tarjeta` pasa porque `riesgos_maria` tiene `CONTROL` sobre `CertColumnas`; `Cajero_ve_los_datos_pero_no_puede_descifrar_la_tarjeta` recibe `403` y el endpoint ya no tiene el atajo que reintentaba como `dbo`.

### Frase de paso

`11_comparacion_cifrado.sql` guarda `'dato de prueba'` con `EncryptByPassPhrase(N'Frase_Demo_2027#', ...)` y luego:

- con la frase correcta, `DecryptByPassPhrase` devuelve `dato de prueba`;
- con `Frase_incorrecta`, devuelve `NULL`.

La frase **es** la clave: no hay certificado, no hay rotación y no hay forma de recuperar el dato si se pierde. Por eso no se usa para las tarjetas.

### Always Encrypted

La cadena real, sin simulación:

1. `pki/crear-cmk.ps1` crea `CN=CMK_BancoAndino` en `CurrentUser\My`. La clave privada **no es exportable** y nunca llega a SQL Server: el motor solo guarda la ruta (`CurrentUser/My/<huella>`).
2. `tools/AeSetup` genera una CEK de 32 bytes y la cifra con RSA-OAEP usando `SqlColumnEncryptionCertificateStoreProvider.EncryptColumnEncryptionKey`, registra `CMK_BancoAndino`/`CEK_BancoAndino` y crea `dbo.ClientesAE`.
3. `16_always_encrypted.sql` declara las columnas: `CI` **determinista** (permite igualdad) y `Nombre`, `SaldoCuenta`, `NumeroTarjeta` **aleatorias** (no permiten filtrar ni ordenar).
4. La aplicación abre dos conexiones con la misma cuenta: una normal y otra con `Column Encryption Setting=Enabled` derivada con `SqlConnectionStringBuilder`. La pantalla *Always Encrypted* muestra la misma fila en los dos modos.

Lo comprobado en la instancia local:

```text
CMK        : CN=CMK_BancoAndino
Ruta       : CurrentUser/My/468588B3E9A96E26A2A85F7C2470BA3480ADCF4D
CEK        : 32 bytes AES-256, cifrada con RSA-OAEP (627 bytes)

Con Column Encryption Setting=Enabled:   8765432 | Ana Quispe | 15.420,50
Sin cifrado en el cliente:               varbinary(65) = 019994DE840E9D34…
```

Y desde `sqlcmd` como `sysadmin`:

```sql
SELECT TOP 1 DATALENGTH(CI) AS bytes_ci, CONVERT(varchar(24), CI, 2) AS prefijo_hex FROM dbo.ClientesAE;
-- 65 | 0x019994DE840E9D34154BF4E787F4F04E83…
```

Las pruebas `Always_encrypted_guarda_binario_y_descifra_solo_en_el_cliente` verifican el alta, la búsqueda por igualdad sobre la columna determinista, que el auditor recibe `403` y que una consulta directa devuelve `byte[]`. En el CI de Linux el script `16` avisa y omite la tabla (no hay almacén de certificados de Windows); la prueba comprueba que el endpoint informa `disponible: false` en lugar de fallar.

**Límites reales de esta implementación:**

- `MSSQL_CERTIFICATE_STORE` es un proveedor de **Windows**. En Linux o en la nube se usa Azure Key Vault (`SqlColumnEncryptionAzureKeyVaultProvider`) con las mismas columnas; el script y la app no cambian, cambia el proveedor.
- Protege del motor, del backup y del DBA, **no del proceso de la aplicación**: quien pueda ejecutar código con la identidad que abre la CMK puede descifrar. Para eso están el control de acceso a la máquina, el mínimo privilegio del servicio y la auditoría.
- Las columnas aleatorias no admiten `WHERE`, `ORDER BY`, `GROUP BY` ni índices; solo la determinista permite igualdad exacta (y revela patrones de repetición, por eso solo se aplica a `CI`).

## Conclusión de diseño

- **TDE** es la base: protege archivos y backups sin tocar la aplicación. Se mantiene.
- **Cifrado por columna** protege el dato más sensible (tarjeta) incluso si alguien lee la tabla, y separa `riesgos` del resto con `CONTROL` sobre el certificado. Se mantiene.
- **Frase de paso** sirve para demostrar el concepto y para datos efímeros; no para PII que deba recuperarse. Queda como laboratorio.
- **Always Encrypted** es la única capa que deja al motor sin texto claro; se usa en `dbo.ClientesAE` y es la respuesta correcta cuando el requisito es “ni el DBA ve el dato”.
