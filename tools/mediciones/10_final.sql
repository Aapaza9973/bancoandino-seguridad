USE BancoAndino;
SET NOCOUNT ON;

-- Estado: 20.000 filas, 1.000 vencidas por caducidad absoluta con uso reciente
-- y 1.000 vencidas por caducidad deslizante (03_muertas.sql).

DECLARE @h CHAR(64), @n INT;
SELECT TOP (1) @h = TokenHash FROM dbo.SesionesApp
 WHERE Revocada = 0
   AND Creada < DATEADD(HOUR, -8, SYSUTCDATETIME())
   AND UltimoUso >= DATEADD(MINUTE, -30, SYSUTCDATETIME());

CREATE TABLE #t (Usuario NVARCHAR(50), NombreCompleto NVARCHAR(100), Rol NVARCHAR(20),
                 PrincipalBD NVARCHAR(128), creada VARCHAR(19), ultimo_uso VARCHAR(19));
INSERT INTO #t EXEC dbo.usp_SesionValidar @TokenHash = @h, @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SELECT @n = COUNT(*) FROM #t;
PRINT CONCAT('resumen validar_vencida_absoluta_devuelve=', @n);
DROP TABLE #t;

CREATE TABLE #c (vigentes INT);
INSERT INTO #c EXEC dbo.usp_SesionContar @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SELECT @n = vigentes FROM #c;
PRINT CONCAT('resumen vigentes_contadas=', @n);
DROP TABLE #c;

DECLARE @antes INT, @login CHAR(64);
SELECT @antes = COUNT(*) FROM dbo.SesionesApp;
SET @login = CONVERT(CHAR(64), HASHBYTES('SHA2_256', 'login-med-final'), 2);
EXEC dbo.usp_SesionCrear
     @TokenHash = @login, @Usuario = 'medlogin', @Nombre = 'Medicion login', @Rol = 'cajero',
     @Principal = 'app_bancoandino', @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SELECT @n = COUNT(*) FROM dbo.SesionesApp;
PRINT CONCAT('resumen filas_antes=', @antes, ' filas_despues=', @n);

-- Las absolutamente vencidas con uso reciente siguen en la tabla; en cuanto su
-- ultimo uso pasa de la vida deslizante, el siguiente login las borra.
UPDATE dbo.SesionesApp
   SET UltimoUso = DATEADD(MINUTE, -45, SYSUTCDATETIME())
 WHERE Revocada = 0
   AND Creada < DATEADD(HOUR, -8, SYSUTCDATETIME());

SELECT @antes = COUNT(*) FROM dbo.SesionesApp;
SET @login = CONVERT(CHAR(64), HASHBYTES('SHA2_256', 'login-med-final-2'), 2);
EXEC dbo.usp_SesionCrear
     @TokenHash = @login, @Usuario = 'medlogin', @Nombre = 'Medicion login', @Rol = 'cajero',
     @Principal = 'app_bancoandino', @VidaMinutos = 30, @VidaAbsolutaHoras = 8;
SELECT @n = COUNT(*) FROM dbo.SesionesApp;
PRINT CONCAT('resumen segundo_login_antes=', @antes, ' despues=', @n);
