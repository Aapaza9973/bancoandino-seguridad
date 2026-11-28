USE BancoAndino;
SET NOCOUNT ON;

EXEC dbo.usp_SesionValidar
     @TokenHash = CONVERT(CHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(20), 1)), 2),
     @VidaMinutos = 30, @VidaAbsolutaHoras = 8;

SELECT OBJECT_NAME(s.object_id) AS procedimiento,
       (SELECT COUNT(*) FROM sys.dm_exec_query_stats q
         WHERE q.sql_handle = s.plan_handle) AS ignorar,
       CAST(qp.query_plan AS NVARCHAR(MAX)) AS plan
  FROM sys.dm_exec_procedure_stats s
 OUTER APPLY sys.dm_exec_query_plan(s.plan_handle) qp
 WHERE s.object_id = OBJECT_ID('dbo.usp_SesionValidar');
