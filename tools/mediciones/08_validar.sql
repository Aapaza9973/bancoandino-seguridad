USE BancoAndino;
SET NOCOUNT ON;

DECLARE @h CHAR(64) = CONVERT(CHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(20), 1)), 2);

SET STATISTICS IO ON;
EXEC dbo.usp_SesionValidar @TokenHash = @h, @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SET STATISTICS IO OFF;
