/* =========================================================
   Control de fuerza bruta - BancoAndino
   La aplicación cuenta los fallos de login y bloquea la cuenta
   temporalmente. Las columnas viven en dbo.UsuariosApp, pero
   quien decide (y sanciona) sigue siendo la aplicación: SQL
   Server solo guarda el estado.
   ========================================================= */
USE BancoAndino;
GO

IF COL_LENGTH('dbo.UsuariosApp', 'IntentosFallidos') IS NULL
BEGIN
    ALTER TABLE dbo.UsuariosApp ADD
        IntentosFallidos INT NOT NULL CONSTRAINT DF_UsuariosApp_Intentos DEFAULT 0,
        BloqueadoHasta   DATETIME2(0) NULL,
        UltimoIntento    DATETIME2(0) NULL;
    PRINT 'Columnas de control de intentos agregadas.';
END
ELSE
    PRINT 'Las columnas ya existían: nada que migrar.';
GO

-- Estado limpio para la demostración.
UPDATE dbo.UsuariosApp SET IntentosFallidos = 0, BloqueadoHasta = NULL;
GO

SELECT Usuario, Activo, IntentosFallidos,
       CONVERT(varchar(19), BloqueadoHasta, 120) AS bloqueado_hasta
FROM dbo.UsuariosApp ORDER BY Usuario;
GO
