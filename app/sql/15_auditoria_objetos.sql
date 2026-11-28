/* =========================================================
   Auditoria consolidada de datos - BancoAndino
   SQL Server permite una sola especificacion de base por
   audit, asi que se reemplaza la de 02 por la version completa.
   Cubre lecturas y escrituras sobre las tablas de datos: un alta
   de cliente o empleado tambien debe quedar en el registro.
   Ejecutar despues de 06_cifrado_columnas.sql.
   ========================================================= */
USE BancoAndino;
GO

IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'AuditSpec_DatosSensibles')
BEGIN
    ALTER DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles WITH (STATE = OFF);
    DROP DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles;
END
GO

CREATE DATABASE AUDIT SPECIFICATION AuditSpec_DatosSensibles
FOR SERVER AUDIT Audit_BancoAndino
ADD (SELECT ON dbo.Clientes             BY public),
ADD (SELECT ON dbo.Empleados            BY public),
ADD (SELECT ON dbo.Transacciones        BY public),
-- Escrituras: un alta, una correccion o una baja tambien dejan rastro,
-- con el principal que la ejecuto (cajero_ana o supervisor_luis).
ADD (INSERT ON dbo.Clientes             BY public),
ADD (UPDATE ON dbo.Clientes             BY public),
ADD (DELETE ON dbo.Clientes             BY public),
ADD (INSERT ON dbo.Empleados            BY public),
ADD (UPDATE ON dbo.Empleados            BY public),
ADD (DELETE ON dbo.Empleados            BY public),
ADD (INSERT ON dbo.Transacciones        BY public),
ADD (UPDATE ON dbo.Transacciones        BY public),
ADD (DELETE ON dbo.Transacciones        BY public),
ADD (SELECT ON dbo.TarjetasCifradas     BY public),
ADD (SELECT ON dbo.TransaccionesFirmadas BY public),
ADD (SELECT ON dbo.UsuariosApp          BY public),
ADD (EXECUTE ON OBJECT::dbo.usp_DescifrarTarjeta BY public),
ADD (DATABASE_PERMISSION_CHANGE_GROUP),
ADD (DATABASE_OBJECT_CHANGE_GROUP),
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
ADD (SCHEMA_OBJECT_CHANGE_GROUP)
WITH (STATE = ON);
GO

SELECT name, is_state_enabled FROM sys.database_audit_specifications;
SELECT audit_action_name, class_desc, major_id, minor_id
FROM sys.database_audit_specification_details ORDER BY audit_action_name;
GO

/* El lector firmado vive en master (la aplicacion lo invoca como
   master.dbo.usp_LeerAuditoria) y el certificado que lo firma tiene
   CONTROL SERVER. Es un objeto de alto valor: cada uso queda auditado
   desde una especificacion de base en master. */
USE master;
GO

IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name = 'AuditSpec_LectorFirmado')
BEGIN
    ALTER DATABASE AUDIT SPECIFICATION AuditSpec_LectorFirmado WITH (STATE = OFF);
    DROP DATABASE AUDIT SPECIFICATION AuditSpec_LectorFirmado;
END
GO

CREATE DATABASE AUDIT SPECIFICATION AuditSpec_LectorFirmado
FOR SERVER AUDIT Audit_BancoAndino
ADD (EXECUTE ON OBJECT::dbo.usp_LeerAuditoria BY public)
WITH (STATE = ON);
GO

SELECT name, is_state_enabled FROM sys.database_audit_specifications WHERE name = 'AuditSpec_LectorFirmado';
SELECT audit_action_name, class_desc, major_id, minor_id
FROM sys.database_audit_specification_details ORDER BY audit_action_name;
GO
