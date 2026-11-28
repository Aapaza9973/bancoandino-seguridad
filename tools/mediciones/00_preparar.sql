USE BancoAndino;
SET NOCOUNT ON;

IF OBJECT_ID('dbo.SesionesApp_med_respaldo') IS NULL
    SELECT * INTO dbo.SesionesApp_med_respaldo FROM dbo.SesionesApp;

TRUNCATE TABLE dbo.SesionesApp;

;WITH n AS (
    SELECT TOP (20000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i
      FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT INTO dbo.SesionesApp
       (TokenHash, Usuario, NombreCompleto, Rol, PrincipalBD, Creada, UltimoUso, Revocada)
SELECT CONVERT(CHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(20), i)), 2),
       'med' + CAST(i AS VARCHAR(10)),
       'Usuario de medicion ' + CAST(i AS VARCHAR(10)),
       'cajero', 'app_bancoandino',
       DATEADD(SECOND, -(i % 28000), SYSUTCDATETIME()),
       DATEADD(SECOND, -(i % 1500), SYSUTCDATETIME()),
       0
  FROM n;

UPDATE STATISTICS dbo.SesionesApp;

SELECT COUNT(*) AS filas_cargadas FROM dbo.SesionesApp;
