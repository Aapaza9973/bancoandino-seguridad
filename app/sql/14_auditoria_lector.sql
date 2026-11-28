/* =========================================================
   Lector de auditoria firmado - BancoAndino
   fn_get_audit_file exige CONTROL SERVER. En vez de darselo a
   la aplicacion, se firma un procedimiento fijo con un
   certificado y se le concede EXECUTE a app_bancoandino.
   Ejecutar despues de 04_tde.sql (necesita la DMK de master).
   ========================================================= */
USE master;
GO

IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'CertAuditoria')
    CREATE CERTIFICATE CertAuditoria
        WITH SUBJECT = 'Lectura controlada de auditoria - BancoAndino';
GO

IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'CertAuditoriaLogin')
    CREATE LOGIN CertAuditoriaLogin FROM CERTIFICATE CertAuditoria;
GO

GRANT CONTROL SERVER TO CertAuditoriaLogin;
GO

CREATE OR ALTER PROCEDURE dbo.usp_LeerAuditoria
    @Top INT = 200
AS
BEGIN
    SET NOCOUNT ON;
    IF @Top < 1 OR @Top > 1000 SET @Top = 200;

    -- La ruta se deriva del propio audit: sirve en Windows y en Linux.
    DECLARE @ruta NVARCHAR(4000) = (
        SELECT log_file_path
               + CASE WHEN RIGHT(log_file_path, 1) IN ('\', '/') THEN ''
                      WHEN CHARINDEX('/', log_file_path) > 0 THEN '/'
                      ELSE '\' END
               + '*'
        FROM sys.server_file_audits
        WHERE name = 'Audit_BancoAndino');

    IF @ruta IS NULL
    BEGIN
        RAISERROR('No existe la auditoria Audit_BancoAndino.', 16, 1);
        RETURN;
    END

    SELECT TOP (@Top) event_time,
           server_principal_name,
           database_principal_name,
           object_name,
           action_id,
           succeeded,
           statement
    FROM sys.fn_get_audit_file(@ruta, DEFAULT, DEFAULT)
    ORDER BY event_time DESC;
END;
GO

IF EXISTS (SELECT 1 FROM sys.crypt_properties
           WHERE major_id = OBJECT_ID('dbo.usp_LeerAuditoria')
             AND thumbprint = CERT_ID('CertAuditoria'))
    DROP SIGNATURE FROM dbo.usp_LeerAuditoria BY CERTIFICATE CertAuditoria;
ADD SIGNATURE TO dbo.usp_LeerAuditoria BY CERTIFICATE CertAuditoria;
GO

IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'app_bancoandino' AND type = 'S')
    GRANT EXECUTE ON dbo.usp_LeerAuditoria TO app_bancoandino;
GO

SELECT p.name AS procedimiento, c.name AS firmado_por
FROM sys.procedures p
CROSS APPLY (SELECT TOP 1 cert.name
             FROM sys.crypt_properties cp
             JOIN sys.certificates cert ON cp.thumbprint = cert.thumbprint
             WHERE cp.major_id = p.object_id AND cp.crypt_type = 'SPVC') c
WHERE p.name = 'usp_LeerAuditoria';
GO
