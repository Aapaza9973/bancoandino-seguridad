/* =========================================================
   Altas de clientes y empleados - BancoAndino
   La consola da de alta clientes y empleados con el mismo
   criterio que el resto del modelo: el permiso vive en el
   motor. La aplicacion suplanta al usuario de la base
   (EXECUTE AS USER) y el INSERT solo pasa si ese usuario
   tiene INSERT sobre la tabla.

   - Cajero: alta de clientes (ya lee la tabla completa).
   - Supervisor: alta de empleados y lectura sin salario, que
     sigue denegado por columna.
   - Riesgos, auditor y DBA no reciben INSERT: no dan de alta.
   Idempotente: se puede reejecutar.
   ========================================================= */
USE BancoAndino;
GO

GRANT INSERT ON dbo.Clientes TO rol_cajero;
GO

GRANT INSERT ON dbo.Empleados TO rol_supervisor;
GRANT SELECT (EmpleadoID, Nombre, CI, Cargo, EmailCorporativo)
      ON dbo.Empleados TO rol_supervisor;
DENY  SELECT (Salario) ON dbo.Empleados TO rol_supervisor;
GO

-- Comprobacion en el contexto real de cada rol.
EXECUTE AS USER = 'cajero_ana';
SELECT USER_NAME() AS principal,
       HAS_PERMS_BY_NAME('dbo.Clientes', 'OBJECT', 'INSERT')  AS insert_clientes,
       HAS_PERMS_BY_NAME('dbo.Empleados', 'OBJECT', 'INSERT') AS insert_empleados;
REVERT;
GO

EXECUTE AS USER = 'supervisor_luis';
SELECT USER_NAME() AS principal,
       HAS_PERMS_BY_NAME('dbo.Clientes', 'OBJECT', 'INSERT')  AS insert_clientes,
       HAS_PERMS_BY_NAME('dbo.Empleados', 'OBJECT', 'INSERT') AS insert_empleados;
REVERT;
GO
