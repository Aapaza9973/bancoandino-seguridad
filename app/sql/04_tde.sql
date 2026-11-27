/* =========================================================
   Cifrado en reposo (TDE) - BancoAndino
   Jerarquia: DPAPI -> SMK -> DMK (master) -> Certificado -> DEK -> archivos
   Ejecutar como sysadmin.
   ========================================================= */
USE master;
GO

-- 1. Clave maestra de la base master (protege al certificado)
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'DMK_Master_BancoAndino2026!';
GO

-- 2. Certificado del servidor para TDE
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'CertBancoAndino')
    CREATE CERTIFICATE CertBancoAndino
        WITH SUBJECT = 'Certificado TDE - BancoAndino',
             EXPIRY_DATE = '2030-12-31';
GO

-- 3. Clave de cifrado de la base (DEK)
USE BancoAndino;
GO
IF NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID())
    CREATE DATABASE ENCRYPTION KEY
        WITH ALGORITHM = AES_256
        ENCRYPTION BY SERVER CERTIFICATE CertBancoAndino;
GO

-- 4. Encender TDE
ALTER DATABASE BancoAndino SET ENCRYPTION ON;
GO

-- 5. Respaldar el certificado y su clave privada (sin esto no se restaura ningun backup)
USE master;
GO
BACKUP CERTIFICATE CertBancoAndino
    TO FILE = 'C:\CertBackup\CertBancoAndino.cer'
    WITH PRIVATE KEY (
        FILE = 'C:\CertBackup\CertBancoAndino_PrivKey.pvk',
        ENCRYPTION BY PASSWORD = 'BackupCert_BancoAndino2026!'
    );
GO

-- 6. Estado
SELECT DB_NAME(dek.database_id) AS base,
       dek.encryption_state_desc  AS estado,
       dek.percent_complete       AS avance,
       dek.key_algorithm          AS algoritmo,
       dek.key_length             AS longitud,
       cert.name                  AS certificado
FROM sys.dm_database_encryption_keys dek
JOIN sys.databases db          ON dek.database_id = db.database_id
LEFT JOIN sys.certificates cert ON dek.encryptor_thumbprint = cert.thumbprint
WHERE db.name = 'BancoAndino';
GO
