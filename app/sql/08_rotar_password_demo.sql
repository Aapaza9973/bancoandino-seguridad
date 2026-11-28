/* =========================================================
   Rotacion de claves de demostracion - BancoAndino
   Vuelve a dejar las cuentas con las claves del README, usando
   PBKDF2-HMAC-SHA256 con sal nueva por usuario. Ejecutar como
   sysadmin despues de 03_usuarios_app.sql.
   ========================================================= */
USE BancoAndino;
GO

UPDATE dbo.UsuariosApp SET
    Sal = 0xdcfc4272a2cd844894fe7b7b1c1a6a29,
    Hash = 0x94021ead9eeb4d644c34470e8931601fc91dabc8d703d02ce38c0ef0196f885f,
    Iteraciones = 210000,
    IntentosFallidos = 0, BloqueadoHasta = NULL, UltimoIntento = NULL
WHERE Usuario = 'ana';

UPDATE dbo.UsuariosApp SET
    Sal = 0xf9204c6f590e508d9ca5e991fc004fd0,
    Hash = 0x8607692a2330481a28eb322f4ab33d27e6a12608a10df835d0f112066cc7c7ec,
    Iteraciones = 210000,
    IntentosFallidos = 0, BloqueadoHasta = NULL, UltimoIntento = NULL
WHERE Usuario = 'luis';

UPDATE dbo.UsuariosApp SET
    Sal = 0xaac7ab6a4fbbe78b7f38da033833d2a6,
    Hash = 0x16f7b19281a4bacfcfe22d938916ea01434a296be436290709544e1d461e5450,
    Iteraciones = 210000,
    IntentosFallidos = 0, BloqueadoHasta = NULL, UltimoIntento = NULL
WHERE Usuario = 'maria';

UPDATE dbo.UsuariosApp SET
    Sal = 0x3570411ec2859731e32c06a5b478e152,
    Hash = 0x5ec3b80cffda9a6087f4e8fdb071a2d6ade654cd2548ce3195150ef83c8204f7,
    Iteraciones = 210000,
    IntentosFallidos = 0, BloqueadoHasta = NULL, UltimoIntento = NULL
WHERE Usuario = 'sofia';

UPDATE dbo.UsuariosApp SET
    Sal = 0x8f2816b68e6dfd9915a4528e2acaf5d1,
    Hash = 0x8587ffaa1b5a4c9e401275c1ce9d53459f4380ae66288e9a8fc98f82ff2de84a,
    Iteraciones = 210000,
    IntentosFallidos = 0, BloqueadoHasta = NULL, UltimoIntento = NULL
WHERE Usuario = 'admin';
GO

SELECT Usuario, Rol, Activo, IntentosFallidos,
       CONVERT(varchar(19), BloqueadoHasta, 120) AS bloqueado_hasta
FROM dbo.UsuariosApp ORDER BY Usuario;
GO
