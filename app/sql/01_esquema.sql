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
GO

CREATE LOGIN cajero_ana      WITH PASSWORD = 'Cajero_Ana_2027#',      CHECK_POLICY = OFF;
CREATE LOGIN supervisor_luis WITH PASSWORD = 'Super_Luis_2027#',     CHECK_POLICY = OFF;
CREATE LOGIN riesgos_maria   WITH PASSWORD = 'Riesgos_Maria_2027#',  CHECK_POLICY = OFF;
CREATE LOGIN auditor_sofia   WITH PASSWORD = 'Auditoria_Sofia_2027#',    CHECK_POLICY = OFF;
CREATE LOGIN dba_admin       WITH PASSWORD = 'Dba_Admin_2027#',      CHECK_POLICY = OFF;
GO

CREATE USER cajero_ana      FOR LOGIN cajero_ana;
CREATE USER supervisor_luis FOR LOGIN supervisor_luis;
CREATE USER riesgos_maria   FOR LOGIN riesgos_maria;
CREATE USER auditor_sofia   FOR LOGIN auditor_sofia;
CREATE USER dba_admin       FOR LOGIN dba_admin;
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
ALTER ROLE db_owner       ADD MEMBER dba_admin;
GO

/* ---------- 4. Permisos (minimo privilegio) ---------- */
-- Cajero: consulta clientes y transacciones; nunca empleados. Ve los datos enmascarados.
GRANT SELECT ON dbo.Clientes      TO rol_cajero;
GRANT SELECT ON dbo.Transacciones TO rol_cajero;
DENY  SELECT ON dbo.Empleados     TO rol_cajero;

-- Supervisor: lo mismo que cajero, sin denegacion explicita de empleados pero sin permiso.
GRANT SELECT ON dbo.Clientes      TO rol_supervisor;
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
GO
