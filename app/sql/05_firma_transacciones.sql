/* =========================================================
   Firma digital de transacciones XML - BancoAndino
   SHA-256 del contenido + firma RSA con certificado del servidor.
   Ejecutar como sysadmin despues de 01_esquema.sql
   ========================================================= */
USE BancoAndino;
GO

-- 1. Clave maestra y certificado de firma
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'DMK_BancoAndino_2026!';
GO

IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'CertTransacciones')
    CREATE CERTIFICATE CertTransacciones
        WITH SUBJECT = 'Firma digital de transacciones - BancoAndino',
             START_DATE = '2026-01-01',
             EXPIRY_DATE = '2030-12-31';
GO

-- 2. Tabla de documentos firmados
IF OBJECT_ID('dbo.TransaccionesFirmadas') IS NOT NULL DROP TABLE dbo.TransaccionesFirmadas;
GO

CREATE TABLE dbo.TransaccionesFirmadas (
    DocID         INT PRIMARY KEY IDENTITY,
    Referencia    CHAR(36)      NOT NULL,
    ClienteID     INT           NOT NULL,
    Monto         DECIMAL(12,2) NOT NULL,
    Tipo          NVARCHAR(20)  NOT NULL,
    FechaTx       DATETIME2     NOT NULL,
    ContenidoXML  XML           NOT NULL,
    HashContenido VARBINARY(32) NOT NULL,
    Firma         VARBINARY(512) NOT NULL,
    CertificadoID INT           NOT NULL,
    FechaFirma    DATETIME2     DEFAULT SYSDATETIME(),
    FirmadoPor    NVARCHAR(128) DEFAULT SUSER_SNAME()
);
GO

-- 3. Firma de una transaccion nueva
CREATE OR ALTER PROCEDURE dbo.usp_FirmarTransaccion
    @ClienteID INT,
    @Monto     DECIMAL(12,2),
    @Tipo      NVARCHAR(20),
    @DocID     INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @ref   CHAR(36)       = LOWER(CONVERT(VARCHAR(36), NEWID()));
    DECLARE @fecha DATETIME2      = SYSDATETIME();
    DECLARE @xml   NVARCHAR(MAX);
    DECLARE @hash  VARBINARY(32);
    DECLARE @firma VARBINARY(512);
    DECLARE @cert  INT = Cert_ID('CertTransacciones');

    SET @xml = '<Transaccion>'
             + '<Referencia>' + @ref + '</Referencia>'
             + '<ClienteID>'  + CAST(@ClienteID AS VARCHAR(10)) + '</ClienteID>'
             + '<Monto>'      + CAST(@Monto AS VARCHAR(20)) + '</Monto>'
             + '<Tipo>'       + @Tipo + '</Tipo>'
             + '<Fecha>'      + CONVERT(VARCHAR(19), @fecha, 120) + '</Fecha>'
             + '</Transaccion>';

    SET @hash  = HASHBYTES('SHA2_256', CAST(@xml AS VARBINARY(MAX)));
    SET @firma = SignByCert(@cert, @hash);

    IF @firma IS NULL
    BEGIN
        RAISERROR('No se pudo firmar: el certificado no tiene clave privada disponible.', 16, 1);
        RETURN;
    END

    INSERT INTO dbo.TransaccionesFirmadas
        (Referencia, ClienteID, Monto, Tipo, FechaTx, ContenidoXML, HashContenido, Firma, CertificadoID)
    VALUES
        (@ref, @ClienteID, @Monto, @Tipo, @fecha, CAST(@xml AS XML), @hash, @firma, @cert);

    SET @DocID = SCOPE_IDENTITY();
END;
GO

-- 4. Alterar el contenido (solo para demostrar la deteccion)
CREATE OR ALTER PROCEDURE dbo.usp_AlterarTransaccion
    @DocID INT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @xml NVARCHAR(MAX);

    SELECT @xml = '<Transaccion>'
                + '<Referencia>' + Referencia + '</Referencia>'
                + '<ClienteID>'  + CAST(ClienteID AS VARCHAR(10)) + '</ClienteID>'
                + '<Monto>99999.99</Monto>'
                + '<Tipo>'       + Tipo + '</Tipo>'
                + '<Fecha>'      + CONVERT(VARCHAR(19), FechaTx, 120) + '</Fecha>'
                + '</Transaccion>'
    FROM dbo.TransaccionesFirmadas WHERE DocID = @DocID;

    UPDATE dbo.TransaccionesFirmadas
       SET ContenidoXML = CAST(@xml AS XML)
     WHERE DocID = @DocID;
END;
GO

-- 5. Restaurar el contenido original desde las columnas del documento
CREATE OR ALTER PROCEDURE dbo.usp_RestaurarTransaccion
    @DocID INT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @xml NVARCHAR(MAX);

    SELECT @xml = '<Transaccion>'
                + '<Referencia>' + Referencia + '</Referencia>'
                + '<ClienteID>'  + CAST(ClienteID AS VARCHAR(10)) + '</ClienteID>'
                + '<Monto>'      + CAST(Monto AS VARCHAR(20)) + '</Monto>'
                + '<Tipo>'       + Tipo + '</Tipo>'
                + '<Fecha>'      + CONVERT(VARCHAR(19), FechaTx, 120) + '</Fecha>'
                + '</Transaccion>'
    FROM dbo.TransaccionesFirmadas WHERE DocID = @DocID;

    UPDATE dbo.TransaccionesFirmadas
       SET ContenidoXML = CAST(@xml AS XML)
     WHERE DocID = @DocID;
END;
GO

-- 6. Vista de verificacion: firma criptografica + integridad del contenido
CREATE OR ALTER VIEW dbo.vw_EstadoFirmas
AS
SELECT  DocID,
        Referencia,
        ClienteID,
        Monto,
        Tipo,
        FechaFirma,
        FirmadoPor,
        Cert_ID('CertTransacciones') AS CertificadoActual,
        VerifySignedByCert(CertificadoID, HashContenido, Firma) AS FirmaValida,
        CASE WHEN HashContenido =
                  HASHBYTES('SHA2_256', CAST(CAST(ContenidoXML AS NVARCHAR(MAX)) AS VARBINARY(MAX)))
             THEN 'INTACTO' ELSE 'ALTERADO' END AS Integridad,
        CONVERT(NVARCHAR(MAX), ContenidoXML) AS Xml
FROM dbo.TransaccionesFirmadas;
GO

-- 7. Permisos de lectura para los roles de la app
GRANT SELECT ON dbo.TransaccionesFirmadas TO rol_cajero, rol_supervisor, rol_riesgos, rol_auditor;
GRANT SELECT ON dbo.vw_EstadoFirmas       TO rol_cajero, rol_supervisor, rol_riesgos, rol_auditor;
GO

SELECT name, subject, expiry_date FROM sys.certificates WHERE name = 'CertTransacciones';
GO
