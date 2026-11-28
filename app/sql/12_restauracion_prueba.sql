/* =========================================================
   Restauracion de prueba - BancoAndino
   Restaura el .bak (cifrado por TDE) en una base aparte y
   verifica estado, integridad, filas y firmas. No toca la
   base BancoAndino en uso.
   Ejecutar con sqlcmd o SSMS en modo SQLCMD.

   En OTRA instancia, antes de restaurar hay que recrear la DMK y el
   certificado con su clave privada (ver 07_backup_antes_de_actualizar.sql):
     RESTORE SERVICE MASTER KEY FROM FILE = '...SMK...' DECRYPTION BY PASSWORD = '...';
     CREATE CERTIFICATE CertBancoAndino FROM FILE = '...cer'
       WITH PRIVATE KEY (FILE = '...pvk', DECRYPTION BY PASSWORD = '...');
   En la misma instancia el certificado ya existe en master.
   ========================================================= */
:setvar BackupFile "C:\BackupBancoAndino\antes_least_privilege\BancoAndino.bak"
:setvar RestoreDb  "BancoAndino_Restaurada"

USE master;
GO

PRINT '== Verificando el backup $(BackupFile)';
RESTORE VERIFYONLY FROM DISK = '$(BackupFile)' WITH CHECKSUM;
GO

IF DB_ID('$(RestoreDb)') IS NOT NULL
BEGIN
    ALTER DATABASE [$(RestoreDb)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [$(RestoreDb)];
END
GO

PRINT '== Restaurando como $(RestoreDb)';
RESTORE DATABASE [$(RestoreDb)]
FROM DISK = '$(BackupFile)'
WITH MOVE 'BancoAndino'     TO 'C:\BackupBancoAndino\BancoAndino_Restaurada.mdf',
     MOVE 'BancoAndino_log' TO 'C:\BackupBancoAndino\BancoAndino_Restaurada_log.ldf',
     REPLACE, RECOVERY, STATS = 10;
GO

PRINT '== Estado de cifrado (debe seguir ENCRYPTED)';
SELECT DB_NAME(dek.database_id) AS base,
       dek.encryption_state_desc AS estado,
       dek.key_algorithm AS algoritmo,
       dek.key_length AS longitud
FROM sys.dm_database_encryption_keys dek
WHERE dek.database_id = DB_ID('$(RestoreDb)');
GO

PRINT '== Integridad estructural';
DBCC CHECKDB('$(RestoreDb)') WITH NO_INFOMSGS;
GO

USE [$(RestoreDb)];
GO

PRINT '== Filas restauradas';
SELECT 'Clientes' AS tabla, COUNT(*) AS filas FROM dbo.Clientes
UNION ALL SELECT 'Transacciones', COUNT(*) FROM dbo.Transacciones
UNION ALL SELECT 'Empleados', COUNT(*) FROM dbo.Empleados
UNION ALL SELECT 'TarjetasCifradas', COUNT(*) FROM dbo.TarjetasCifradas;
GO

PRINT '== Firmas del backup restaurado';
SELECT DocID, FirmaValida, Integridad FROM dbo.vw_EstadoFirmas;
GO

PRINT 'La base $(RestoreDb) quedo restaurada. Para limpiar: DROP DATABASE [$(RestoreDb)];';
