/* =========================================================
   Auditoria de accesos - BancoAndino
   Ejecutar como sysadmin despues de 01_esquema.sql
   Requiere que exista la carpeta C:\AuditLogs\BancoAndino
   ========================================================= */
USE master;
GO

IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = 'Audit_BancoAndino')
BEGIN
    ALTER SERVER AUDIT Audit_BancoAndino WITH (STATE = OFF);
    DROP SERVER AUDIT Audit_BancoAndino;
END
GO

CREATE SERVER AUDIT Audit_BancoAndino
    TO FILE (FILEPATH = 'C:\AuditLogs\BancoAndino\',
             MAXSIZE = 20 MB,
             MAX_FILES = 10,
             RESERVE_DISK_SPACE = OFF)
    WITH (ON_FAILURE = CONTINUE);
GO

ALTER SERVER AUDIT Audit_BancoAndino WITH (STATE = ON);
GO

USE BancoAndino;
GO

IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'AuditSpec_DatosSensibles')
    DROP DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles;
GO

-- Registra todo SELECT sobre las tablas con datos personales y financieros
CREATE DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles
FOR SERVER AUDIT Audit_BancoAndino
ADD (SELECT ON dbo.Clientes      BY public),
ADD (SELECT ON dbo.Empleados     BY public),
ADD (SELECT ON dbo.Transacciones BY public)
WITH (STATE = ON);
GO

SELECT name, is_state_enabled FROM sys.server_audits;
SELECT name, is_state_enabled FROM sys.database_audit_specifications;
GO
