USE BancoAndino;
SET NOCOUNT ON;

DECLARE @h CHAR(64) = CONVERT(CHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(20), 1)), 2);
EXEC dbo.usp_SesionValidar @TokenHash = @h, @VidaMinutos = 30, @VidaAbsolutaHoras = 8;

DECLARE @p NVARCHAR(MAX) = (
    SELECT CAST(qp.query_plan AS NVARCHAR(MAX))
      FROM sys.dm_exec_procedure_stats s
     OUTER APPLY sys.dm_exec_query_plan(s.plan_handle) qp
     WHERE s.object_id = OBJECT_ID('dbo.usp_SesionValidar'));

PRINT CONCAT('plan_bytes=', DATALENGTH(@p));
IF @p LIKE '%IX_SesionesApp_Vigentes_Uso%'    PRINT 'mantiene IX_SesionesApp_Vigentes_Uso';
IF @p LIKE '%IX_SesionesApp_Vigentes_Creada%' PRINT 'mantiene IX_SesionesApp_Vigentes_Creada';
IF @p LIKE '%IX_SesionesApp_Revocadas%'       PRINT 'mantiene IX_SesionesApp_Revocadas';
IF @p LIKE '%Clustered Index Update%'         PRINT 'actualiza el indice clustered (PK)';
IF @p LIKE '%Index Seek%'                     PRINT 'usa Index Seek';
