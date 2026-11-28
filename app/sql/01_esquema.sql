/* =========================================================
   PROYECTO - SEGURIDAD INFORMATICA
   Banco Andino S.A. - Esquema, datos y modelo de seguridad
   Ejecutar una sola vez como sysadmin (SSMS o sqlcmd -E).
   ========================================================= */

IF DB_ID('BancoAndino') IS NULL
    CREATE DATABASE BancoAndino;
GO
USE BancoAndino;
GO

/* ---------- 1. Tablas ---------- */
IF OBJECT_ID('dbo.Transacciones') IS NOT NULL DROP TABLE dbo.Transacciones;
IF OBJECT_ID('dbo.Empleados')     IS NOT NULL DROP TABLE dbo.Empleados;
IF OBJECT_ID('dbo.Clientes')      IS NOT NULL DROP TABLE dbo.Clientes;
GO

CREATE TABLE dbo.Clientes (
    ClienteID     INT PRIMARY KEY IDENTITY,
    Nombre        NVARCHAR(100) NOT NULL,
    CI            CHAR(9)       NOT NULL,
    Email         NVARCHAR(150) NOT NULL,
    Telefono      CHAR(8)       NOT NULL,
    NumeroTarjeta CHAR(19)      NOT NULL,
    SaldoCuenta   DECIMAL(12,2) NOT NULL
);

CREATE TABLE dbo.Transacciones (
    TxID      INT PRIMARY KEY IDENTITY,
    ClienteID INT NOT NULL REFERENCES dbo.Clientes(ClienteID),
    Monto     DECIMAL(12,2) NOT NULL,
    Tipo      NVARCHAR(20)  NOT NULL,
    FechaTx   DATETIME2     DEFAULT SYSDATETIME()
);

CREATE TABLE dbo.Empleados (
    EmpleadoID       INT PRIMARY KEY IDENTITY,
    Nombre           NVARCHAR(100) NOT NULL,
    CI               CHAR(9)       NOT NULL,
    Cargo            NVARCHAR(60)  NOT NULL,
    Salario          DECIMAL(10,2) NOT NULL,
    EmailCorporativo NVARCHAR(150) NOT NULL
);
GO

INSERT INTO dbo.Clientes (Nombre, CI, Email, Telefono, NumeroTarjeta, SaldoCuenta) VALUES
 ('Ana Quispe',    '8765432', 'ana.quispe@correo.bo',  '72341100', '4532-1122-3344-5566', 15420.50),
 ('Luis Mamani',   '1234567', 'luis.mamani@gmail.com', '71234567', '5489-9988-7766-1234',  8750.00),
 ('Sofia Vargas',  '9876543', 'sofia.vargas@lab.bo',   '76543210', '4111-0000-1111-2222', 32100.75),
 ('Pedro Rios',    '7654321', 'pedro.rios@correo.bo',  '70001122', '6011-3344-5566-7788',  4300.00),
 ('Maria Condori', '2345678', 'maria.condori@lab.bo',  '73334455', '4556-7788-9900-1122',  980.25);

INSERT INTO dbo.Transacciones (ClienteID, Monto, Tipo) VALUES
 (1, -500.00, 'Pago servicio'), (1, 2000.00, 'Deposito'),
 (2, -1200.00, 'Compra'),       (3, -80.00,  'Pago internet'),
 (3, 5000.00, 'Deposito'),      (4, -300.00, 'Retiro'),
 (5, 150.00,  'Deposito'),      (2, -950.00, 'Transferencia');

INSERT INTO dbo.Empleados (Nombre, CI, Cargo, Salario, EmailCorporativo) VALUES
 ('Ana Quispe',    '8765432', 'Cajera',     4800.00, 'a.quispe@bancoandino.bo'),
 ('Carlos Flores', '1234567', 'Supervisor', 9200.00, 'c.flores@bancoandino.bo'),
 ('Maria Condori', '9876543', 'Jefa de Riesgos', 14500.00, 'm.condori@bancoandino.bo'),
 ('Jorge Ticona',  '4567891', 'Auditor Interno', 11000.00, 'j.ticona@bancoandino.bo');
GO

/* ---------- 2. Enmascaramiento dinamico (DDM) ---------- */
ALTER TABLE dbo.Clientes ALTER COLUMN NumeroTarjeta
    ADD MASKED WITH (FUNCTION = 'partial(0,"XXXX-XXXX-XXXX-",4)');
ALTER TABLE dbo.Clientes ALTER COLUMN Email
    ADD MASKED WITH (FUNCTION = 'email()');
ALTER TABLE dbo.Clientes ALTER COLUMN Telefono
    ADD MASKED WITH (FUNCTION = 'partial(0,"XXXX",4)');
ALTER TABLE dbo.Clientes ALTER COLUMN SaldoCuenta
    ADD MASKED WITH (FUNCTION = 'default()');
ALTER TABLE dbo.Clientes ALTER COLUMN CI
    ADD MASKED WITH (FUNCTION = 'partial(2,"XXXXXXX",0)');

ALTER TABLE dbo.Empleados ALTER COLUMN CI
    ADD MASKED WITH (FUNCTION = 'partial(2,"XXXXXXX",0)');
ALTER TABLE dbo.Empleados ALTER COLUMN Salario
    ADD MASKED WITH (FUNCTION = 'default()');
ALTER TABLE dbo.Empleados ALTER COLUMN EmailCorporativo
    ADD MASKED WITH (FUNCTION = 'email()');
GO

/* ---------- 3. Logins, usuarios y roles ---------- */
IF SUSER_ID('cajero_ana')      IS NOT NULL DROP LOGIN cajero_ana;
IF SUSER_ID('supervisor_luis') IS NOT NULL DROP LOGIN supervisor_luis;
IF SUSER_ID('riesgos_maria')   IS NOT NULL DROP LOGIN riesgos_maria;
IF SUSER_ID('auditor_sofia')   IS NOT NULL DROP LOGIN auditor_sofia;
IF SUSER_ID('dba_admin')       IS NOT NULL DROP LOGIN dba_admin;
IF SUSER_ID('app_bancoandino') IS NOT NULL DROP LOGIN app_bancoandino;
GO

-- CHECK_POLICY = ON: las claves cumplen la politica del servidor. Ojo:
-- la politica rechaza una clave que contenga el nombre del login, y eso
-- solo se aplica en un motor con la politica activa (el contenedor Linux
-- la aplica siempre). Por eso ninguna clave repite su login.
-- CHECK_EXPIRATION = OFF para que la demo no caduque a los 90 dias.
CREATE LOGIN cajero_ana      WITH PASSWORD = 'Caj3ro.Andino#27',      CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;
CREATE LOGIN supervisor_luis WITH PASSWORD = 'Sup3rvisor.Andino#27',  CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;
CREATE LOGIN riesgos_maria   WITH PASSWORD = 'Ri3sgos.Andino#27',    CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;
CREATE LOGIN auditor_sofia   WITH PASSWORD = 'Aud1tor.Andino#27',    CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;
CREATE LOGIN dba_admin       WITH PASSWORD = 'Adm1n.Andino#27',      CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;

-- Cuenta de conexion de la aplicacion: sin sysadmin ni db_owner.
CREATE LOGIN app_bancoandino WITH PASSWORD = 'Apl1cacion.Andino#27',  CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;
GO

CREATE USER cajero_ana      FOR LOGIN cajero_ana;
CREATE USER supervisor_luis FOR LOGIN supervisor_luis;
CREATE USER riesgos_maria   FOR LOGIN riesgos_maria;
CREATE USER auditor_sofia   FOR LOGIN auditor_sofia;
CREATE USER dba_admin       FOR LOGIN dba_admin;
CREATE USER app_bancoandino FOR LOGIN app_bancoandino;
GO

CREATE ROLE rol_cajero;
CREATE ROLE rol_supervisor;
CREATE ROLE rol_riesgos;
CREATE ROLE rol_auditor;
GO

ALTER ROLE rol_cajero     ADD MEMBER cajero_ana;
ALTER ROLE rol_supervisor ADD MEMBER supervisor_luis;
ALTER ROLE rol_riesgos    ADD MEMBER riesgos_maria;
ALTER ROLE rol_auditor    ADD MEMBER auditor_sofia;
GO

-- El DBA ya no es db_owner: ve metadatos (C) pero no lee datos por si mismo.
GRANT VIEW DEFINITION TO dba_admin;

-- La aplicacion suplanta a los cinco usuarios y ejecuta solo los
-- procedimientos que necesita. No tiene SELECT directo sobre las tablas.
GRANT IMPERSONATE ON USER::cajero_ana      TO app_bancoandino;
GRANT IMPERSONATE ON USER::supervisor_luis TO app_bancoandino;
GRANT IMPERSONATE ON USER::riesgos_maria   TO app_bancoandino;
GRANT IMPERSONATE ON USER::auditor_sofia   TO app_bancoandino;
GRANT IMPERSONATE ON USER::dba_admin       TO app_bancoandino;
GRANT VIEW DEFINITION TO app_bancoandino;
GO

/* ---------- 4. Permisos (minimo privilegio) ---------- */
-- Cajero: clientes y transacciones completas (enmascaradas). De empleados solo
-- las columnas de atencion: el salario se deniega por columna.
GRANT SELECT ON dbo.Clientes      TO rol_cajero;
GRANT SELECT ON dbo.Transacciones TO rol_cajero;
GRANT SELECT (EmpleadoID, Nombre, CI, Cargo, EmailCorporativo)
      ON dbo.Empleados TO rol_cajero;
DENY  SELECT (Salario) ON dbo.Empleados TO rol_cajero;

-- Supervisor: transacciones completas; en clientes pierde la columna de tarjeta
-- (no la ve ni enmascarada) y conserva el resto bajo DDM.
GRANT SELECT (ClienteID, Nombre, CI, Email, Telefono, SaldoCuenta)
      ON dbo.Clientes TO rol_supervisor;
DENY  SELECT (NumeroTarjeta) ON dbo.Clientes TO rol_supervisor;
GRANT SELECT ON dbo.Transacciones TO rol_supervisor;

-- Riesgos: ve todo, y por UNMASK ve los datos reales de clientes.
GRANT SELECT ON dbo.Clientes      TO rol_riesgos;
GRANT SELECT ON dbo.Transacciones TO rol_riesgos;
GRANT SELECT ON dbo.Empleados     TO rol_riesgos;
GRANT UNMASK TO rol_riesgos;

-- Auditor: solo lectura de todo, siempre enmascarado (no tiene UNMASK).
GRANT SELECT ON dbo.Clientes      TO rol_auditor;
GRANT SELECT ON dbo.Transacciones TO rol_auditor;
GRANT SELECT ON dbo.Empleados     TO rol_auditor;
GO

/* ---------- 5. Verificacion ---------- */
SELECT dp.name AS usuario, rp.name AS rol
FROM sys.database_role_members rm
JOIN sys.database_principals dp ON rm.member_principal_id = dp.principal_id
JOIN sys.database_principals rp ON rm.role_principal_id   = rp.principal_id
ORDER BY rp.name, dp.name;

SELECT OBJECT_NAME(mc.object_id) AS tabla, mc.name AS columna, mc.masking_function
FROM sys.masked_columns mc ORDER BY tabla, columna;

-- Permisos por columna (minor_id > 0): GRANT y DENY que no son de tabla
SELECT OBJECT_NAME(p.major_id) AS tabla,
       COL_NAME(p.major_id, p.minor_id) AS columna,
       dp.name AS principal,
       p.permission_name AS permiso,
       p.state_desc AS estado
FROM sys.database_permissions p
JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
WHERE p.class = 1 AND p.minor_id > 0
ORDER BY tabla, columna, principal;
GO

/* ---------- 6. Cuenta de aplicacion en master ---------- */
-- VIEW SERVER STATE: estado de TDE (DMV). VIEW DEFINITION: metadatos del
-- certificado TDE. No se concede ningun permiso sobre datos de usuario.
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'app_bancoandino')
    CREATE USER app_bancoandino FOR LOGIN app_bancoandino;
GRANT VIEW SERVER STATE TO app_bancoandino;
GRANT VIEW DEFINITION ON DATABASE::master TO app_bancoandino;
GO
USE BancoAndino;
GO
