#!/usr/bin/env bash
# =========================================================
# Replica local del CI - BancoAndino
#
# Ejecuta exactamente la misma secuencia que
# .github/workflows/ci-bancoandino.yml sobre un SQL Server
# 2022 limpio en Docker, y despues corre las pruebas con la
# cuenta app_bancoandino (sin sysadmin ni db_owner).
#
# Sirve para validar el workflow cuando GitHub Actions no
# puede correr (por ejemplo, facturacion bloqueada).
#
# Uso: bash tools/verificar-ci-local.sh
# =========================================================
set -euo pipefail

CONTENEDOR="${CONTENEDOR:-bancoandino-ci}"
PUERTO="${PUERTO:-14330}"
SA_PASS="${SA_PASS:-BancoAndino_Ci2026!}"
AUDIT_DIR='/var/opt/mssql/audit/'
SQLCMD='/opt/mssql-tools18/bin/sqlcmd'

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

echo "== 1/5 SQL Server 2022 limpio en contenedor"
docker rm -f "$CONTENEDOR" >/dev/null 2>&1 || true
docker run -d --name "$CONTENEDOR" \
  -e ACCEPT_EULA=Y \
  -e MSSQL_SA_PASSWORD="$SA_PASS" \
  -e MSSQL_PID=Developer \
  -p "${PUERTO}:1433" \
  mcr.microsoft.com/mssql/server:2022-latest >/dev/null

for i in $(seq 1 60); do
  if MSYS2_ARG_CONV_EXCL='*' docker exec "$CONTENEDOR" "$SQLCMD" -S localhost -U sa -P "$SA_PASS" -C -Q "SELECT 1" >/dev/null 2>&1; then
    echo "   motor listo"
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    echo "   el motor no respondio"; docker logs "$CONTENEDOR" | tail -30; exit 1
  fi
done

echo "== 2/5 Carpeta de auditoria"
MSYS2_ARG_CONV_EXCL='*' docker exec -u root "$CONTENEDOR" mkdir -p "$AUDIT_DIR"
MSYS2_ARG_CONV_EXCL='*' docker exec -u root "$CONTENEDOR" chown mssql:mssql "$AUDIT_DIR"

echo "== 3/5 Esquema, seguridad y auditoria"
for archivo in 01_esquema.sql 03_usuarios_app.sql 05_firma_transacciones.sql \
               06_cifrado_columnas.sql 10_demo_sqli.sql 13_admin_procs.sql \
               17_sesiones.sql 18_metadatos.sql; do
  echo "   $archivo"
  MSYS2_ARG_CONV_EXCL='*' docker exec -i "$CONTENEDOR" "$SQLCMD" \
    -S localhost -U sa -P "$SA_PASS" -C -b < "app/sql/$archivo" > /dev/null
done

echo "   app/sql/02_auditoria.sql"
MSYS2_ARG_CONV_EXCL='*' docker exec -i "$CONTENEDOR" "$SQLCMD" \
  -S localhost -U sa -P "$SA_PASS" -C -b -v AuditDir="$AUDIT_DIR" \
  < app/sql/02_auditoria.sql > /dev/null

echo "== 4/5 TDE, datos de prueba y lector de auditoria"
for archivo in ci/40_tde_ci.sql ci/50_seed_ci.sql 14_auditoria_lector.sql \
               15_auditoria_objetos.sql 16_always_encrypted.sql; do
  echo "   $archivo"
  MSYS2_ARG_CONV_EXCL='*' docker exec -i "$CONTENEDOR" "$SQLCMD" \
    -S localhost -U sa -P "$SA_PASS" -C -b < "app/sql/$archivo" > /dev/null
done

echo "== 5/5 Pruebas contra la instancia del CI"
export ConnectionStrings__BancoAndino="Server=127.0.0.1,${PUERTO};Database=BancoAndino;User Id=app_bancoandino;Password=Apl1cacion.Andino#27;TrustServerCertificate=True;Encrypt=False;Application Name=BancoAndinoCi"
dotnet test tests/BancoAndino.Tests/BancoAndino.Tests.csproj --nologo -v q

echo ""
echo "CI local completo. Para limpiar: docker rm -f $CONTENEDOR"
