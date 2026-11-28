USE BancoAndino;
SET NOCOUNT ON;

DECLARE @h CHAR(64) = CONVERT(CHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(20), 1)), 2);

SET STATISTICS IO ON;
SET STATISTICS TIME ON;
EXEC dbo.usp_SesionValidar @TokenHash = @h, @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SET STATISTICS TIME OFF;
SET STATISTICS IO OFF;

-- 1.000 llamadas: el resultado se guarda en una tabla para no enviarlo al cliente.
CREATE TABLE #r (Usuario NVARCHAR(50), NombreCompleto NVARCHAR(100), Rol NVARCHAR(20),
                 PrincipalBD NVARCHAR(128), creada VARCHAR(19), ultimo_uso VARCHAR(19));
DECLARE @i INT = 0, @t0 DATETIME2(7) = SYSDATETIME();
WHILE @i < 1000
BEGIN
    INSERT INTO #r EXEC dbo.usp_SesionValidar @TokenHash = @h, @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
    DELETE FROM #r;
    SET @i += 1;
END;
PRINT CONCAT('resumen us_por_llamada=', DATEDIFF(MICROSECOND, @t0, SYSDATETIME()) / 1000.0);
DROP TABLE #r;
