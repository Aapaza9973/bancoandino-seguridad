USE BancoAndino;
SET NOCOUNT ON;

/* Comprobacion previa del arnes de mediciones.
   No modifica nada: solo consulta permisos efectivos del login conectado.
   El arnes vacia SesionesApp, crea y borra indices filtrados y actualiza
   estadisticas, asi que necesita ALTER sobre la tabla (TRUNCATE TABLE,
   CREATE/DROP INDEX y UPDATE STATISTICS comparten ese permiso).
   app_bancoandino solo tiene EXECUTE sobre los usp_Sesion*, no alcanza. */

DECLARE @login sysname = SUSER_SNAME();
DECLARE @faltan NVARCHAR(1500) = N'';

IF HAS_PERMS_BY_NAME('dbo.SesionesApp', 'OBJECT', 'ALTER') = 0
    SET @faltan += N' ALTER sobre dbo.SesionesApp (TRUNCATE TABLE, CREATE/DROP INDEX, UPDATE STATISTICS);';
IF HAS_PERMS_BY_NAME('dbo.SesionesApp', 'OBJECT', 'SELECT') = 0
    SET @faltan += N' SELECT sobre dbo.SesionesApp (respaldo y conteos);';
IF HAS_PERMS_BY_NAME('dbo.SesionesApp', 'OBJECT', 'INSERT') = 0
    SET @faltan += N' INSERT sobre dbo.SesionesApp (carga de las 20.000 filas);';
IF HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE TABLE') = 0
    SET @faltan += N' CREATE TABLE en BancoAndino (tabla SesionesApp_med_respaldo);';
IF HAS_PERMS_BY_NAME('dbo', 'SCHEMA', 'ALTER') = 0
    SET @faltan += N' ALTER sobre el esquema dbo (borrar la tabla de respaldo);';

IF @faltan <> N''
BEGIN
    DECLARE @msg NVARCHAR(2048) = CONCAT(
        N'PERMISOS INSUFICIENTES: el login ', @login, N' no puede correr las mediciones. Falta:',
        @faltan,
        N' Se necesita un login sysadmin o dbo; app_bancoandino no alcanza.',
        N' No se modifico nada.');
    THROW 50001, @msg, 1;
END

SELECT CONCAT('permisos_ok|', @login) AS comprobacion;
