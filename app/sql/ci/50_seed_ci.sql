/* =========================================================
   Datos minimos para que las pruebas de CI tengan que validar:
   un documento firmado y las tarjetas cifradas ya vienen de
   05_firma_transacciones.sql y 06_cifrado_columnas.sql.
   ========================================================= */
USE BancoAndino;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.TransaccionesFirmadas)
BEGIN
    DECLARE @doc INT;
    EXEC dbo.usp_FirmarTransaccion @ClienteID = 1, @Monto = 950.00, @Tipo = 'Transferencia', @DocID = @doc OUTPUT;
    PRINT 'Documento firmado de ejemplo: ' + CAST(@doc AS VARCHAR(10));
END
GO

SELECT (SELECT COUNT(*) FROM dbo.TransaccionesFirmadas) AS firmadas,
       (SELECT COUNT(*) FROM dbo.TarjetasCifradas)      AS tarjetas,
       (SELECT COUNT(*) FROM dbo.UsuariosApp)           AS usuarios;
GO
