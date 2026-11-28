/* =========================================================
   Comparacion de estrategias de cifrado - BancoAndino
   - TDE: cifra archivos y backups (04_tde.sql).
   - Por columna con clave simetrica: clave protegida por
     certificado (06_cifrado_columnas.sql).
   - Con frase de paso: EncryptByPassPhrase, sin jerarquia de
     claves; la clave es la frase que se escribe en cada uso.
   - Always Encrypted: el motor nunca ve el dato en claro; la
     clave vive en el cliente. Se documenta, no se implementa
     aqui porque requiere un almacen de claves del cliente.
   ========================================================= */
USE BancoAndino;
GO

IF OBJECT_ID('dbo.NotasPassphrase') IS NOT NULL DROP TABLE dbo.NotasPassphrase;
GO

CREATE TABLE dbo.NotasPassphrase (
    NotaID  INT IDENTITY PRIMARY KEY,
    Texto   VARBINARY(256) NOT NULL,
    Fecha   DATETIME2 DEFAULT SYSDATETIME()
);
GO

-- Guardar: el texto se cifra con la frase; no hay certificado ni clave persistente.
CREATE OR ALTER PROCEDURE dbo.usp_GuardarNotaPassphrase
    @Texto      NVARCHAR(100),
    @Passphrase NVARCHAR(100),
    @NotaID     INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.NotasPassphrase (Texto)
    VALUES (EncryptByPassPhrase(@Passphrase, @Texto));
    SET @NotaID = SCOPE_IDENTITY();
END;
GO

-- Leer: sin la frase correcta, DecryptByPassPhrase devuelve NULL.
CREATE OR ALTER PROCEDURE dbo.usp_LeerNotaPassphrase
    @NotaID     INT,
    @Passphrase NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT NotaID,
           CONVERT(NVARCHAR(100), DecryptByPassPhrase(@Passphrase, Texto)) AS Texto,
           DATALENGTH(Texto) AS bytes
    FROM dbo.NotasPassphrase
    WHERE NotaID = @NotaID;
END;
GO

GRANT EXECUTE ON dbo.usp_GuardarNotaPassphrase TO app_bancoandino;
GRANT EXECUTE ON dbo.usp_LeerNotaPassphrase    TO app_bancoandino;
GO

-- Prueba de ida y vuelta (la frase no se guarda en ningun lado).
DECLARE @id INT;
EXEC dbo.usp_GuardarNotaPassphrase N'dato de prueba', N'Frase_Demo_2027#', @id OUTPUT;
EXEC dbo.usp_LeerNotaPassphrase @id, N'Frase_Demo_2027#';
EXEC dbo.usp_LeerNotaPassphrase @id, N'Frase_incorrecta';
GO
