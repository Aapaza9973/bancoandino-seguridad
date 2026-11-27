/* =========================================================
   Usuarios de la aplicacion - BancoAndino
   La contrasena no se guarda en claro: se guarda HASHBYTES
   de (sal + contrasena). La autorizacion NO vive aqui:
   vive en los permisos y mascaras de SQL Server.
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
    Sal                 VARCHAR(24)  NOT NULL,
    Hash            VARBINARY(32) NOT NULL,
    Activo          BIT NOT NULL DEFAULT 1
);
GO

INSERT INTO dbo.UsuariosApp (Usuario, NombreCompleto, PrincipalBD, Rol, Sal, Hash) VALUES
 ('ana',     'Ana Quispe',      'cajero_ana',      'cajero',     'sal-ana-2026-0001',      HASHBYTES('SHA2_256', N'sal-ana-2026-0001' + N'Cajero_Ana2026!')),
 ('luis',    'Luis Mamani',     'supervisor_luis', 'supervisor', 'sal-luis-2026-002',      HASHBYTES('SHA2_256', N'sal-luis-2026-002' + N'Super_Luis2026!')),
 ('maria',   'Maria Condori',   'riesgos_maria',   'riesgos',    'sal-maria-2026-003',     HASHBYTES('SHA2_256', N'sal-maria-2026-003' + N'Riesgos_Maria2026!')),
 ('sofia',   'Sofia Vargas',    'auditor_sofia',   'auditor',    'sal-sofia-2026-004',     HASHBYTES('SHA2_256', N'sal-sofia-2026-004' + N'Audit_Sofia2026!')),
 ('admin',   'Administrador TI','dba_admin',       'dba',        'sal-admin-2026-005',     HASHBYTES('SHA2_256', N'sal-admin-2026-005' + N'Dba_Admin2026!'));
GO

SELECT Usuario, NombreCompleto, PrincipalBD, Rol, Activo, DATALENGTH(Hash) AS bytes_hash
FROM dbo.UsuariosApp ORDER BY Rol;
GO
