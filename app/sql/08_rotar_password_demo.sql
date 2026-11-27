/* Rotacion de las contrasenas de demostracion (quedaron publicadas en el repo).
   No cambia permisos ni roles: solo la clave de cada principal y el hash de la app. */
USE BancoAndino;
GO
ALTER LOGIN cajero_ana      WITH PASSWORD = 'Cajero_Ana_2027#';
ALTER LOGIN supervisor_luis WITH PASSWORD = 'Super_Luis_2027#';
ALTER LOGIN riesgos_maria   WITH PASSWORD = 'Riesgos_Maria_2027#';
ALTER LOGIN auditor_sofia   WITH PASSWORD = 'Auditoria_Sofia_2027#';
ALTER LOGIN dba_admin       WITH PASSWORD = 'Dba_Admin_2027#';
GO
UPDATE dbo.UsuariosApp SET Hash = HASHBYTES('SHA2_256', N'sal-ana-2026-0001'   + N'Cajero_Ana_2027#')    WHERE Usuario = 'ana';
UPDATE dbo.UsuariosApp SET Hash = HASHBYTES('SHA2_256', N'sal-luis-2026-002'   + N'Super_Luis_2027#')    WHERE Usuario = 'luis';
UPDATE dbo.UsuariosApp SET Hash = HASHBYTES('SHA2_256', N'sal-maria-2026-003'  + N'Riesgos_Maria_2027#') WHERE Usuario = 'maria';
UPDATE dbo.UsuariosApp SET Hash = HASHBYTES('SHA2_256', N'sal-sofia-2026-004'  + N'Auditoria_Sofia_2027#') WHERE Usuario = 'sofia';
UPDATE dbo.UsuariosApp SET Hash = HASHBYTES('SHA2_256', N'sal-admin-2026-005'  + N'Dba_Admin_2027#')    WHERE Usuario = 'admin';
GO
SELECT Usuario, Rol, Activo, DATALENGTH(Hash) AS bytes FROM dbo.UsuariosApp ORDER BY Rol;
GO
