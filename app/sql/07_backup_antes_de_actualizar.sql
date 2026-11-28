-- Respaldo previo a cambiar de edicion (Evaluation -> Developer)
USE master;
GO
BACKUP SERVICE MASTER KEY TO FILE = 'C:/BackupBancoAndino/20261127_145344/SMK_BancoAndino.key'
    ENCRYPTION BY PASSWORD = 'BackupCert_BancoAndino2026!';
BACKUP CERTIFICATE CertBancoAndino TO FILE = 'C:/BackupBancoAndino/20261127_145344/CertBancoAndino.cer'
    WITH PRIVATE KEY (FILE = 'C:/BackupBancoAndino/20261127_145344/CertBancoAndino.pvk', ENCRYPTION BY PASSWORD = 'BackupCert_BancoAndino2026!');
GO
BACKUP DATABASE BancoAndino TO DISK = 'C:/BackupBancoAndino/20261127_145344/BancoAndino_antes_developer.bak'
    WITH INIT, COMPRESSION, CHECKSUM,
         ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = CertBancoAndino);
GO
RESTORE VERIFYONLY FROM DISK = 'C:/BackupBancoAndino/20261127_145344/BancoAndino_antes_developer.bak' WITH CHECKSUM;
GO
