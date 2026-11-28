USE BancoAndino;
SET NOCOUNT ON;

TRUNCATE TABLE dbo.SesionesApp;
INSERT INTO dbo.SesionesApp
       (TokenHash, Usuario, NombreCompleto, Rol, PrincipalBD, Creada, UltimoUso, Revocada)
SELECT TokenHash, Usuario, NombreCompleto, Rol, PrincipalBD, Creada, UltimoUso, Revocada
  FROM dbo.SesionesApp_med_respaldo;

DROP TABLE dbo.SesionesApp_med_respaldo;
UPDATE STATISTICS dbo.SesionesApp;

SELECT COUNT(*) AS sesiones_restauradas FROM dbo.SesionesApp;
