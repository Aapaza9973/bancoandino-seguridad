/* =========================================================
   Sesiones persistentes - BancoAndino
   La sesion deja de vivir en la memoria del proceso: se guarda
   en una tabla y sobrevive a un reinicio o a un segundo nodo de
   la aplicacion. Lo que se guarda es el SHA-256 del token, no el
   token: un volcado de la tabla no permite reutilizar sesiones.

   Caducidad deslizante y absoluta las aplica el motor, no el
   proceso. Ejecutar despues de 01_esquema.sql.
   ========================================================= */
USE BancoAndino;
GO

IF OBJECT_ID('dbo.SesionesApp') IS NULL
CREATE TABLE dbo.SesionesApp (
    TokenHash      CHAR(64)      NOT NULL PRIMARY KEY,   -- SHA-256 en hexadecimal
    Usuario        NVARCHAR(50)  NOT NULL,
    NombreCompleto NVARCHAR(100) NOT NULL,
    Rol            NVARCHAR(20)  NOT NULL,
    PrincipalBD    NVARCHAR(128) NOT NULL,
    Creada         DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    UltimoUso      DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    Revocada       BIT           NOT NULL DEFAULT 0
);
GO

CREATE OR ALTER PROCEDURE dbo.usp_SesionCrear
    @TokenHash         CHAR(64),
    @Usuario           NVARCHAR(50),
    @Nombre            NVARCHAR(100),
    @Rol               NVARCHAR(20),
    @Principal         NVARCHAR(128),
    @VidaMinutos       INT = 30,
    @VidaAbsolutaHoras INT = 8
AS
BEGIN
    SET NOCOUNT ON;

    -- Higiene en el login, no en cada request: cerradas, vencidas por
    -- inactividad o por tiempo absoluto.
    DELETE FROM dbo.SesionesApp
     WHERE Revocada = 1
        OR DATEADD(HOUR, @VidaAbsolutaHoras, Creada) < SYSUTCDATETIME()
        OR DATEADD(MINUTE, @VidaMinutos, UltimoUso) < SYSUTCDATETIME();

    INSERT INTO dbo.SesionesApp (TokenHash, Usuario, NombreCompleto, Rol, PrincipalBD)
    VALUES (@TokenHash, @Usuario, @Nombre, @Rol, @Principal);
END;
GO

CREATE OR ALTER PROCEDURE dbo.usp_SesionValidar
    @TokenHash         CHAR(64),
    @VidaMinutos       INT = 30,
    @VidaAbsolutaHoras INT = 8
AS
BEGIN
    SET NOCOUNT ON;

    -- Camino caliente: una sola escritura y ningun barrido de tabla.
    -- La caducidad se evalua en el WHERE, asi que una sesion vencida o
    -- revocada no se renueva ni se devuelve; sus filas se borran en el
    -- siguiente login (usp_SesionCrear).
    UPDATE dbo.SesionesApp
       SET UltimoUso = SYSUTCDATETIME()
    OUTPUT inserted.Usuario, inserted.NombreCompleto, inserted.Rol, inserted.PrincipalBD,
           CONVERT(varchar(19), inserted.Creada, 120)    AS creada,
           CONVERT(varchar(19), inserted.UltimoUso, 120) AS ultimo_uso
     WHERE TokenHash = @TokenHash
       AND Revocada = 0
       AND DATEADD(HOUR, @VidaAbsolutaHoras, Creada) >= SYSUTCDATETIME()
       AND DATEADD(MINUTE, @VidaMinutos, UltimoUso) >= SYSUTCDATETIME();
END;
GO

CREATE OR ALTER PROCEDURE dbo.usp_SesionCerrar
    @TokenHash CHAR(64)
AS
BEGIN
    SET NOCOUNT ON;
    DELETE FROM dbo.SesionesApp WHERE TokenHash = @TokenHash;
END;
GO

CREATE OR ALTER PROCEDURE dbo.usp_SesionContar
    @VidaMinutos       INT = 30,
    @VidaAbsolutaHoras INT = 8
AS
BEGIN
    SET NOCOUNT ON;

    -- Vigente = no revocada y no vencida. Las filas muertas siguen en la
    -- tabla hasta el siguiente login, que es donde se limpian.
    SELECT COUNT(*) AS vigentes
      FROM dbo.SesionesApp
     WHERE Revocada = 0
       AND DATEADD(HOUR, @VidaAbsolutaHoras, Creada) >= SYSUTCDATETIME()
       AND DATEADD(MINUTE, @VidaMinutos, UltimoUso) >= SYSUTCDATETIME();
END;
GO

CREATE OR ALTER PROCEDURE dbo.usp_SesionRevocarTodas
    @VidaMinutos       INT = 30,
    @VidaAbsolutaHoras INT = 8
AS
BEGIN
    SET NOCOUNT ON;

    -- Se informan solo las que estaban vivas: las vencidas siguen en la tabla
    -- hasta el proximo login y no son una sesion que se este cerrando.
    DECLARE @revocadas INT = (
        SELECT COUNT(*) FROM dbo.SesionesApp
         WHERE Revocada = 0
           AND DATEADD(HOUR, @VidaAbsolutaHoras, Creada) >= SYSUTCDATETIME()
           AND DATEADD(MINUTE, @VidaMinutos, UltimoUso) >= SYSUTCDATETIME());

    UPDATE dbo.SesionesApp SET Revocada = 1 WHERE Revocada = 0;

    SELECT @revocadas AS revocadas;
END;
GO

GRANT EXECUTE ON dbo.usp_SesionCrear        TO app_bancoandino;
GRANT EXECUTE ON dbo.usp_SesionValidar      TO app_bancoandino;
GRANT EXECUTE ON dbo.usp_SesionCerrar       TO app_bancoandino;
GRANT EXECUTE ON dbo.usp_SesionContar       TO app_bancoandino;
GRANT EXECUTE ON dbo.usp_SesionRevocarTodas TO app_bancoandino;
GO

SELECT COUNT(*) AS sesiones_vigentes
FROM dbo.SesionesApp WHERE Revocada = 0;
GO
