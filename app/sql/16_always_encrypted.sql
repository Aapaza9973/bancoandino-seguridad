/* =========================================================
   Always Encrypted - BancoAndino
   Las claves (CMK en el almacen del cliente y CEK) no se pueden
   crear desde T-SQL: la CEK se cifra con la clave publica del
   certificado en el equipo del cliente. Para eso esta la
   herramienta tools/AeSetup, que crea CMK_BancoAndino y
   CEK_BancoAndino y siembra filas de ejemplo.

   Este script (idempotente) crea la tabla cifrada y sus permisos.
   Si la CEK todavia no existe, avisa y no hace nada: asi el CI de
   Linux puede ejecutar la secuencia completa sin el almacen de
   certificados de Windows. La tabla y los GRANT van en SQL dinamico
   porque SQL Server resuelve CEK_BancoAndino al compilar el lote,
   aunque la rama no se ejecute.

   Orden: pki/crear-cmk.ps1  ->  dotnet run --project tools/AeSetup
          ->  este script
   ========================================================= */
USE BancoAndino;
SET NOCOUNT ON;

IF NOT EXISTS (SELECT 1 FROM sys.column_encryption_keys WHERE name = 'CEK_BancoAndino')
BEGIN
    PRINT 'Always Encrypted: falta CEK_BancoAndino; ejecuta tools/AeSetup. Se omite la tabla dbo.ClientesAE.';
END
ELSE
BEGIN
    IF OBJECT_ID('dbo.ClientesAE') IS NULL
        EXEC (N'CREATE TABLE dbo.ClientesAE (
            ClienteID     INT PRIMARY KEY IDENTITY,
            CI            CHAR(9) COLLATE Latin1_General_BIN2
                          ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = CEK_BancoAndino,
                                          ENCRYPTION_TYPE = Deterministic,
                                          ALGORITHM = ''AEAD_AES_256_CBC_HMAC_SHA_256'') NOT NULL,
            Nombre        NVARCHAR(100) COLLATE Latin1_General_BIN2
                          ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = CEK_BancoAndino,
                                          ENCRYPTION_TYPE = Randomized,
                                          ALGORITHM = ''AEAD_AES_256_CBC_HMAC_SHA_256'') NOT NULL,
            SaldoCuenta   DECIMAL(12,2)
                          ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = CEK_BancoAndino,
                                          ENCRYPTION_TYPE = Randomized,
                                          ALGORITHM = ''AEAD_AES_256_CBC_HMAC_SHA_256'') NOT NULL,
            NumeroTarjeta CHAR(19) COLLATE Latin1_General_BIN2
                          ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = CEK_BancoAndino,
                                          ENCRYPTION_TYPE = Randomized,
                                          ALGORITHM = ''AEAD_AES_256_CBC_HMAC_SHA_256'') NOT NULL,
            FechaAlta     DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
        );');

    -- El auditor queda fuera a proposito: ve los metadatos del cifrado
    -- (18_metadatos.sql) pero no descifra el contenido.
    EXEC (N'GRANT SELECT, INSERT ON dbo.ClientesAE TO rol_cajero, rol_riesgos;');
    EXEC (N'DENY SELECT ON dbo.ClientesAE TO rol_auditor;');
    EXEC (N'DENY SELECT ON dbo.ClientesAE TO rol_supervisor;');

    PRINT 'dbo.ClientesAE lista: CI determinista, nombre/saldo/tarjeta aleatorios.';
END;

SELECT cmk.name AS clave_maestra, cmk.key_store_provider_name AS proveedor, cmk.key_path AS ruta
FROM sys.column_master_keys cmk;

SELECT cek.name AS clave_columna,
       cmk.name AS clave_maestra,
       v.encryption_algorithm_name AS algoritmo,
       DATALENGTH(v.encrypted_value) AS bytes_cifrados
FROM sys.column_encryption_keys cek
JOIN sys.column_encryption_key_values v ON v.column_encryption_key_id = cek.column_encryption_key_id
JOIN sys.column_master_keys cmk         ON cmk.column_master_key_id = v.column_master_key_id;

SELECT c.name AS columna, c.encryption_type_desc AS tipo,
       c.encryption_algorithm_name AS algoritmo,
       c.collation_name AS collation
FROM sys.columns c
WHERE c.object_id = OBJECT_ID('dbo.ClientesAE') AND c.encryption_type IS NOT NULL
ORDER BY c.column_id;
