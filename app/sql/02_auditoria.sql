/* =========================================================
   Auditoria de accesos - BancoAndino
   Ejecutar como sysadmin despues de 01_esquema.sql
   Requiere que exista la carpeta indicada en la variable AuditDir.
   Local:  -v AuditDir='C:\AuditLogs\BancoAndino\'
   CI:     -v AuditDir=/var/opt/mssql/audit/
   ========================================================= */

-- 1. Quitar primero las especificaciones: un audit con especificaciones
--    activas no se puede eliminar.
USE BancoAndino;
GO
IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'AuditSpec_DatosSensibles')
BEGIN
    ALTER DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles WITH (STATE = OFF);
    DROP DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles;
END
GO

USE master;
GO
IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name = 'AuditSpec_Servidor')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION AuditSpec_Servidor WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION AuditSpec_Servidor;
END
GO

IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name = 'Audit_BancoAndino')
BEGIN
    ALTER SERVER AUDIT Audit_BancoAndino WITH (STATE = OFF);
    DROP SERVER AUDIT Audit_BancoAndino;
END
GO

-- 2. Audit nuevo, con escritura inmediata para ver una denegacion al instante.
CREATE SERVER AUDIT Audit_BancoAndino
    TO FILE (FILEPATH = '$(AuditDir)',
             MAXSIZE = 20 MB,
             MAX_FILES = 10,
             RESERVE_DISK_SPACE = OFF)
    WITH (ON_FAILURE = CONTINUE, QUEUE_DELAY = 0);
GO

ALTER SERVER AUDIT Audit_BancoAndino WITH (STATE = ON);
GO

-- 3. Inicios de sesion fallidos y exitosos (nivel servidor)
CREATE SERVER AUDIT SPECIFICATION AuditSpec_Servidor
FOR SERVER AUDIT Audit_BancoAndino
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP)
WITH (STATE = ON);
GO

USE BancoAndino;
GO

-- 4. SELECT sobre datos personales/financieros y cambios de permisos,
--    mascaras, roles y objetos.
CREATE DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles
FOR SERVER AUDIT Audit_BancoAndino
ADD (SELECT ON dbo.Clientes      BY public),
ADD (SELECT ON dbo.Empleados     BY public),
ADD (SELECT ON dbo.Transacciones BY public),
ADD (DATABASE_PERMISSION_CHANGE_GROUP),
ADD (DATABASE_OBJECT_CHANGE_GROUP),
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
ADD (SCHEMA_OBJECT_CHANGE_GROUP)
WITH (STATE = ON);
GO

-- El lector controlado del archivo vive en 14_auditoria_lector.sql,
-- porque el certificado que lo firma necesita la DMK creada en 04.

SELECT name, is_state_enabled FROM sys.server_audits;
SELECT name, is_state_enabled FROM sys.server_audit_specifications;
USE BancoAndino;
SELECT name, is_state_enabled FROM sys.database_audit_specifications;
GO
