/* =========================================================
   Usuarios de la aplicacion - BancoAndino
   La contrasena no se guarda en claro: se guarda PBKDF2-HMAC-
   SHA256 (210.000 iteraciones) con una sal aleatoria por usuario.
   La verificacion se hace en la aplicacion; SQL Server solo
   guarda sal, hash e iteraciones. La autorizacion sigue viviendo
   en los permisos y mascaras del motor.
   ========================================================= */
USE BancoAndino;
GO

IF OBJECT_ID('dbo.UsuariosApp') IS NOT NULL DROP TABLE dbo.UsuariosApp;
GO

CREATE TABLE dbo.UsuariosApp (
    Usuario         VARCHAR(30)  PRIMARY KEY,
    NombreCompleto  NVARCHAR(100) NOT NULL,
    PrincipalBD     VARCHAR(30)  NOT NULL,   -- usuario de la base que se suplanta
    Rol             VARCHAR(20)  NOT NULL,   -- cajero | supervisor | riesgos | auditor | dba
    Sal             VARBINARY(16) NOT NULL,  -- sal aleatoria por usuario
    Hash            VARBINARY(32) NOT NULL,  -- PBKDF2-HMAC-SHA256
    Iteraciones     INT NOT NULL DEFAULT 210000,
    Activo          BIT NOT NULL DEFAULT 1,
    -- Control de fuerza bruta: la aplicacion bloquea la cuenta tras N fallos.
    IntentosFallidos INT NOT NULL DEFAULT 0,
    BloqueadoHasta   DATETIME2(0) NULL,
    UltimoIntento    DATETIME2(0) NULL
);
GO

-- Hashes de demostracion (claves del README). Rotar con 08 antes de un uso real.
INSERT INTO dbo.UsuariosApp (Usuario, NombreCompleto, PrincipalBD, Rol, Sal, Hash, Iteraciones) VALUES
 ('ana',   'Ana Quispe',       'cajero_ana',      'cajero',
  0xdcfc4272a2cd844894fe7b7b1c1a6a29, 0x94021ead9eeb4d644c34470e8931601fc91dabc8d703d02ce38c0ef0196f885f, 210000),
 ('luis',  'Luis Mamani',      'supervisor_luis', 'supervisor',
  0xf9204c6f590e508d9ca5e991fc004fd0, 0x8607692a2330481a28eb322f4ab33d27e6a12608a10df835d0f112066cc7c7ec, 210000),
 ('maria', 'Maria Condori',    'riesgos_maria',   'riesgos',
  0xaac7ab6a4fbbe78b7f38da033833d2a6, 0x16f7b19281a4bacfcfe22d938916ea01434a296be436290709544e1d461e5450, 210000),
 ('sofia', 'Sofia Vargas',     'auditor_sofia',   'auditor',
  0x3570411ec2859731e32c06a5b478e152, 0x5ec3b80cffda9a6087f4e8fdb071a2d6ade654cd2548ce3195150ef83c8204f7, 210000),
 ('admin', 'Administrador TI', 'dba_admin',       'dba',
  0x8f2816b68e6dfd9915a4528e2acaf5d1, 0x8587ffaa1b5a4c9e401275c1ce9d53459f4380ae66288e9a8fc98f82ff2de84a, 210000);
GO

-- La aplicacion solo lee y actualiza el estado de las cuentas.
GRANT SELECT, UPDATE ON dbo.UsuariosApp TO app_bancoandino;
GO

SELECT Usuario, NombreCompleto, PrincipalBD, Rol, Activo,
       DATALENGTH(Sal) AS bytes_sal, DATALENGTH(Hash) AS bytes_hash, Iteraciones
FROM dbo.UsuariosApp ORDER BY Rol;
GO
