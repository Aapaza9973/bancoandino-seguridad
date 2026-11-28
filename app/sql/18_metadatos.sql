/* =========================================================
   Metadatos para el auditor (cierre B5) - BancoAndino
   El auditor necesita ver la ACL, las mascaras y las columnas
   para poder auditar el modelo, no los datos. VIEW DEFINITION
   le permite leer sys.database_permissions, sys.masked_columns
   y sys.columns en su propio contexto; no le da SELECT sobre
   ninguna tabla ni permiso para cambiar nada.

   Lo que sigue sin poder hacer: leer filas (solo tiene SELECT
   enmascarado), cambiar permisos (no es db_owner) ni abrir la
   CMK de Always Encrypted (el certificado vive fuera del motor).
   ========================================================= */
USE BancoAndino;
GO

GRANT VIEW DEFINITION TO rol_auditor;
GO

-- Comprobacion en el contexto real del auditor: mismo calculo que
-- hace la aplicacion antes de mostrar la pantalla de metadatos.
EXECUTE AS USER = 'auditor_sofia';
SELECT USER_NAME() AS principal,
       HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION') AS view_definition,
       HAS_PERMS_BY_NAME('dbo.Clientes', 'OBJECT', 'SELECT')       AS select_clientes,
       HAS_PERMS_BY_NAME('dbo.Clientes', 'OBJECT', 'ALTER')        AS alter_clientes,
       (SELECT COUNT(*) FROM sys.masked_columns)                   AS mascaras_visibles,
       (SELECT COUNT(*) FROM sys.database_permissions p
         JOIN sys.database_principals d ON p.grantee_principal_id = d.principal_id
        WHERE d.name NOT IN ('dbo', 'public'))                     AS permisos_visibles;
REVERT;
GO

SELECT dp.name AS principal, p.permission_name AS permiso, p.state_desc AS estado
FROM sys.database_permissions p
JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
WHERE dp.name = 'rol_auditor' AND p.class = 0
ORDER BY p.permission_name;
GO
