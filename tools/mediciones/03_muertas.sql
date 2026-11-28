USE BancoAndino;
SET NOCOUNT ON;

-- 1.000 absolutamente vencidas pero usadas hace un minuto: solo las alcanza el
-- DELETE por Creada (el UPDATE de usp_SesionValidar ya no las renueva).
UPDATE s
   SET Creada    = DATEADD(HOUR, -9, SYSUTCDATETIME()),
       UltimoUso = DATEADD(MINUTE, -1, SYSUTCDATETIME())
  FROM dbo.SesionesApp s
  JOIN (SELECT TOP (1000) TokenHash FROM dbo.SesionesApp
         WHERE Revocada = 0 ORDER BY TokenHash) x
    ON x.TokenHash = s.TokenHash;

-- 1.000 vencidas por caducidad deslizante: las alcanza el DELETE por UltimoUso.
UPDATE s
   SET UltimoUso = DATEADD(MINUTE, -45, SYSUTCDATETIME())
  FROM dbo.SesionesApp s
  JOIN (SELECT TOP (1000) TokenHash FROM dbo.SesionesApp
         WHERE Revocada = 0
           AND Creada >= DATEADD(HOUR, -8, SYSUTCDATETIME())
           AND UltimoUso >= DATEADD(MINUTE, -30, SYSUTCDATETIME())
         ORDER BY TokenHash DESC) x
    ON x.TokenHash = s.TokenHash;

SELECT COUNT(*) AS absolutas_vencidas
  FROM dbo.SesionesApp
 WHERE Revocada = 0
   AND Creada < DATEADD(HOUR, -8, SYSUTCDATETIME())
   AND UltimoUso >= DATEADD(MINUTE, -30, SYSUTCDATETIME());
SELECT COUNT(*) AS deslizantes_vencidas
  FROM dbo.SesionesApp
 WHERE Revocada = 0
   AND Creada >= DATEADD(HOUR, -8, SYSUTCDATETIME())
   AND UltimoUso < DATEADD(MINUTE, -30, SYSUTCDATETIME());
