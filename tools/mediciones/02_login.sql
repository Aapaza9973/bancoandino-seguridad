USE BancoAndino;
SET NOCOUNT ON;

DECLARE @h CHAR(64) = CONVERT(CHAR(64), HASHBYTES('SHA2_256', 'login-med-0'), 2);

SET STATISTICS IO ON;
SET STATISTICS TIME ON;
EXEC dbo.usp_SesionCrear
     @TokenHash = @h, @Usuario = 'medlogin', @Nombre = 'Medicion login', @Rol = 'cajero',
     @Principal = 'app_bancoandino', @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SET STATISTICS TIME OFF;
SET STATISTICS IO OFF;

-- 50 logins seguidos con tokens distintos: costo sostenido del barrido.
DECLARE @i INT = 1, @t0 DATETIME2(7) = SYSDATETIME(), @t CHAR(64);
WHILE @i <= 50
BEGIN
    SET @t = CONVERT(CHAR(64), HASHBYTES('SHA2_256', CONCAT('login-med-', @i)), 2);
    EXEC dbo.usp_SesionCrear
         @TokenHash = @t, @Usuario = 'medlogin', @Nombre = 'Medicion login', @Rol = 'cajero',
         @Principal = 'app_bancoandino', @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
    SET @i += 1;
END;
PRINT CONCAT('resumen us_por_login=', DATEDIFF(MICROSECOND, @t0, SYSDATETIME()) / 50000.0);

DELETE FROM dbo.SesionesApp WHERE Usuario = 'medlogin';
