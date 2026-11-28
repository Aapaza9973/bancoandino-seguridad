/* =========================================================
   Demostracion de SQL injection - BancoAndino
   Dos procedimientos con la misma firma y el mismo objetivo:
   buscar clientes por nombre. Uno concatena el filtro en el
   texto de la consulta; el otro lo pasa como parametro.
   Solo administracion puede ejecutarlos.
   Ejecutar despues de 06_cifrado_columnas.sql.
   ========================================================= */
USE BancoAndino;
GO

-- VULNERABLE: el filtro se pega al texto de la consulta.
CREATE OR ALTER PROCEDURE dbo.usp_BuscarClienteVulnerable
    @Nombre NVARCHAR(100)
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @sql NVARCHAR(MAX) =
        N'SELECT TOP 5 ClienteID, Nombre FROM dbo.Clientes WHERE Nombre = ''' + @Nombre + N''';';

    EXEC (@sql);   -- concatenacion: el valor puede cambiar la consulta
END;
GO

-- SEGURO: el filtro viaja como parametro y nunca se interpreta como SQL.
CREATE OR ALTER PROCEDURE dbo.usp_BuscarClienteSeguro
    @Nombre NVARCHAR(100)
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;

    SELECT TOP 5 ClienteID, Nombre
    FROM dbo.Clientes
    WHERE Nombre = @Nombre;
END;
GO

GRANT EXECUTE ON dbo.usp_BuscarClienteVulnerable TO dba_admin;
GRANT EXECUTE ON dbo.usp_BuscarClienteSeguro      TO dba_admin;
GO

SELECT name, type_desc FROM sys.objects
WHERE name IN ('usp_BuscarClienteVulnerable', 'usp_BuscarClienteSeguro');
GO
