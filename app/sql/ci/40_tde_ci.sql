/* =========================================================
   TDE para integracion continua (Linux)
   Igual que 04_tde.sql pero sin BACKUP CERTIFICATE a C:\,
   que no existe en el contenedor. El respaldo del certificado
   se hace solo en la instancia local de desarrollo.
   ========================================================= */
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'DMK_Master_BancoAndino2026!';
GO

IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'CertBancoAndino')
    CREATE CERTIFICATE CertBancoAndino
        WITH SUBJECT = 'Certificado TDE - BancoAndino',
             EXPIRY_DATE = '2030-12-31';
GO

USE BancoAndino;
GO

IF NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID())
    CREATE DATABASE ENCRYPTION KEY
        WITH ALGORITHM = AES_256
        ENCRYPTION BY SERVER CERTIFICATE CertBancoAndino;
GO

ALTER DATABASE BancoAndino SET ENCRYPTION ON;
GO
