/* =========================================================
   Cifrado a nivel de columna - BancoAndino
   Tarjeta y CVV cifrados con clave simetrica AES-256.
   La clave la abre solo quien tiene CONTROL sobre ella:
   tener SELECT sobre la tabla NO alcanza para descifrar.
   Ejecutar como sysadmin despues de 05_firma_transacciones.sql
   ========================================================= */
USE BancoAndino;
GO

-- 1. Certificado que protege la clave simetrica
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'CertColumnas')
    CREATE CERTIFICATE CertColumnas
        WITH SUBJECT = 'Cifrado por columna - datos de tarjeta',
             EXPIRY_DATE = '2030-12-31';
GO

-- 2. Clave simetrica AES-256 protegida por el certificado
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = 'SK_Tarjetas')
    CREATE SYMMETRIC KEY SK_Tarjetas
        WITH ALGORITHM = AES_256
        ENCRYPTION BY CERTIFICATE CertColumnas;
GO

-- 3. Tabla con las columnas cifradas
IF OBJECT_ID('dbo.TarjetasCifradas') IS NOT NULL DROP TABLE dbo.TarjetasCifradas;
GO

CREATE TABLE dbo.TarjetasCifradas (
    TarjetaID    INT PRIMARY KEY IDENTITY,
    ClienteID    INT           NOT NULL REFERENCES dbo.Clientes(ClienteID),
    Ultimos4     CHAR(4)       NOT NULL,          -- referencia visible, no es el dato
    NumeroCifrado VARBINARY(256) NOT NULL,
    CVVCifrado    VARBINARY(128) NOT NULL,
    FechaAlta    DATETIME2     DEFAULT SYSDATETIME()
);
GO

-- 4. Guardar una tarjeta (cifra dentro del motor)
CREATE OR ALTER PROCEDURE dbo.usp_GuardarTarjeta
    @ClienteID INT,
    @Numero    NVARCHAR(19),
    @CVV       NVARCHAR(4),
    @TarjetaID INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    OPEN SYMMETRIC KEY SK_Tarjetas DECRYPTION BY CERTIFICATE CertColumnas;

    INSERT INTO dbo.TarjetasCifradas (ClienteID, Ultimos4, NumeroCifrado, CVVCifrado)
    VALUES (@ClienteID, RIGHT(@Numero, 4),
            EncryptByKey(Key_GUID('SK_Tarjetas'), @Numero),
            EncryptByKey(Key_GUID('SK_Tarjetas'), @CVV));

    SET @TarjetaID = SCOPE_IDENTITY();
    CLOSE SYMMETRIC KEY SK_Tarjetas;
END;
GO

-- 5. Leer y descifrar (falla si el usuario no puede abrir la clave)
CREATE OR ALTER PROCEDURE dbo.usp_DescifrarTarjeta
    @TarjetaID INT
AS
BEGIN
    SET NOCOUNT ON;
    OPEN SYMMETRIC KEY SK_Tarjetas DECRYPTION BY CERTIFICATE CertColumnas;

    SELECT TarjetaID,
           ClienteID,
           Ultimos4,
           CONVERT(NVARCHAR(19), DecryptByKey(NumeroCifrado)) AS Numero,
           CONVERT(NVARCHAR(4),  DecryptByKey(CVVCifrado))    AS CVV
    FROM dbo.TarjetasCifradas
    WHERE TarjetaID = @TarjetaID;

    CLOSE SYMMETRIC KEY SK_Tarjetas;
END;
GO

-- 6. Permisos: todos leen la tabla, solo riesgos (y el dba) abren la clave
GRANT SELECT ON dbo.TarjetasCifradas TO rol_cajero, rol_supervisor, rol_riesgos, rol_auditor;
GRANT EXECUTE ON dbo.usp_DescifrarTarjeta TO rol_cajero, rol_supervisor, rol_riesgos, rol_auditor;

GRANT CONTROL ON CERTIFICATE::CertColumnas TO rol_riesgos;
GRANT CONTROL ON SYMMETRIC KEY::SK_Tarjetas TO rol_riesgos;
GO

-- 7. Dos tarjetas de ejemplo
DECLARE @id INT;
EXEC dbo.usp_GuardarTarjeta 1, '4532-1122-3344-5566', '123', @id OUTPUT;
EXEC dbo.usp_GuardarTarjeta 2, '5489-9988-7766-1234', '456', @id OUTPUT;

SELECT TarjetaID, ClienteID, Ultimos4,
       DATALENGTH(NumeroCifrado) AS bytes_numero,
       DATALENGTH(CVVCifrado)    AS bytes_cvv
FROM dbo.TarjetasCifradas;
GO
