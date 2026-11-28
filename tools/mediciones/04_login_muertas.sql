USE BancoAndino;
SET NOCOUNT ON;

DECLARE @h CHAR(64) = CONVERT(CHAR(64), HASHBYTES('SHA2_256', 'login-med-muertas'), 2);

SET STATISTICS IO ON;
SET STATISTICS TIME ON;
EXEC dbo.usp_SesionCrear
     @TokenHash = @h, @Usuario = 'medlogin', @Nombre = 'Medicion login', @Rol = 'cajero',
     @Principal = 'app_bancoandino', @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SET STATISTICS TIME OFF;
SET STATISTICS IO OFF;

DECLARE @n INT;
SELECT @n = COUNT(*) FROM dbo.SesionesApp;
PRINT CONCAT('resumen filas_restantes=', @n);
