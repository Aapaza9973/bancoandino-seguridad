/* =========================================================
   Administracion sin db_owner - BancoAndino
   La aplicacion (app_bancoandino) no es sysadmin ni db_owner.
   Estos procedimientos son la unica via para cambiar permisos
   o mascaras: validan la entrada y se ejecutan como el dueno
   (dbo), que si tiene CONTROL sobre la base.
   Ejecutar despues de 06_cifrado_columnas.sql.
   ========================================================= */
USE BancoAndino;
GO

CREATE OR ALTER PROCEDURE dbo.usp_AdminPermiso
    @Accion    VARCHAR(10),
    @Permiso   VARCHAR(10),
    @Tabla     SYSNAME,
    @Principal SYSNAME
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    SET @Accion  = UPPER(LTRIM(RTRIM(@Accion)));
    SET @Permiso = UPPER(LTRIM(RTRIM(@Permiso)));

    IF @Accion NOT IN ('GRANT', 'DENY', 'REVOKE')
        THROW 50001, 'Accion no valida: use GRANT, DENY o REVOKE.', 1;
    IF @Permiso NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
        THROW 50002, 'Permiso no valido.', 1;
    IF @Tabla NOT IN ('Clientes', 'Transacciones', 'Empleados')
        THROW 50003, 'Tabla no valida.', 1;
    IF @Principal IS NULL OR LEN(@Principal) > 30
       OR @Principal LIKE '%[^A-Za-z0-9_]%'
        THROW 50004, 'Principal no valido.', 1;

    DECLARE @sql NVARCHAR(400) =
        @Accion + ' ' + @Permiso + ' ON dbo.' + QUOTENAME(@Tabla) +
        ' TO ' + QUOTENAME(@Principal) + ';';

    EXEC (@sql);
    SELECT @sql AS ejecutado;
END;
GO

CREATE OR ALTER PROCEDURE dbo.usp_AdminMascara
    @Tabla   SYSNAME,
    @Columna SYSNAME,
    @Funcion NVARCHAR(100) = N''
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    IF @Tabla NOT IN ('Clientes', 'Empleados')
        THROW 50011, 'Tabla no valida para mascaras.', 1;
    IF NOT EXISTS (SELECT 1 FROM sys.columns
                   WHERE object_id = OBJECT_ID('dbo.' + @Tabla) AND name = @Columna)
        THROW 50012, 'Columna no valida.', 1;
    IF @Funcion <> N'' AND @Funcion NOT IN (
        N'default()', N'email()', N'random(1, 9999)',
        N'partial(0,"XXXX-XXXX-XXXX-",4)', N'partial(0,"XXXX",4)',
        N'partial(2,"XXXXXXX",0)')
        THROW 50013, 'Funcion de enmascaramiento no valida.', 1;

    DECLARE @sql NVARCHAR(500);
    IF @Funcion = N''
        SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@Tabla) +
                   N' ALTER COLUMN ' + QUOTENAME(@Columna) + N' DROP MASKED;';
    ELSE
        SET @sql = N'ALTER TABLE dbo.' + QUOTENAME(@Tabla) +
                   N' ALTER COLUMN ' + QUOTENAME(@Columna) +
                   N' ADD MASKED WITH (FUNCTION = ''' + @Funcion + N''');';

    EXEC (@sql);
    SELECT @sql AS ejecutado;
END;
GO

GRANT EXECUTE ON dbo.usp_AdminPermiso TO app_bancoandino;
GRANT EXECUTE ON dbo.usp_AdminMascara TO app_bancoandino;
GRANT EXECUTE ON dbo.usp_AdminPermiso TO dba_admin;
GRANT EXECUTE ON dbo.usp_AdminMascara TO dba_admin;
GO

SELECT name, type_desc FROM sys.objects
WHERE name IN ('usp_AdminPermiso', 'usp_AdminMascara');
GO
