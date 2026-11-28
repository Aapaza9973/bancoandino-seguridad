#!/usr/bin/env bash
# =========================================================
# Restauracion en OTRA instancia - BancoAndino
#
# 1. Respalda la base cifrada con TDE.
# 2. Levanta un SQL Server 2022 limpio en un contenedor (su propia SMK).
# 3. Traslada el .bak y el certificado TDE con su clave privada.
# 4. Restaura y verifica cifrado, integridad, filas, firmas y la
#    tabla de Always Encrypted (que sigue siendo binario).
#
# El certificado viaja como binario por SQL (CERTENCODED /
# CERTPRIVATEKEY) porque SQL Server crea los .cer/.pvk con una ACL
# que solo su cuenta de servicio puede leer; el .bak si es legible.
# La instancia destino re-cifra la clave privada con su propia SMK,
# por eso no hace falta exportar la SMK del origen: la SMK es por
# instancia, lo que debe viajar es el certificado TDE.
#
# Uso: bash tools/verificar-restauracion-otra-instancia.sh
# Requiere: docker, sqlcmd y una instancia local con la base.
# =========================================================
set -euo pipefail

CONTENEDOR="${CONTENEDOR:-bancoandino-otra}"
PUERTO="${PUERTO:-14331}"
SA_PASS="${SA_PASS:-Otra_Instancia_2026!}"
CLAVE_CERT='Traslado_BancoAndino_2026!'
SQLCMD_CONTENEDOR='/opt/mssql-tools18/bin/sqlcmd'

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Cada corrida usa su propia carpeta: SQL Server es dueno de los archivos que
# crea y no siempre se pueden borrar desde la sesion del usuario.
SELLO="$(date +%Y%m%d_%H%M%S)"
CARPETA_WIN="C:\\BackupBancoAndino\\otra_instancia\\${SELLO}"
CARPETA="/c/BackupBancoAndino/otra_instancia/${SELLO}"

echo "== 1/5 Respaldo cifrado y exportacion del certificado"
mkdir -p "$CARPETA"
mkdir -p "$RAIZ/.tmp"

cat > "$RAIZ/.tmp/respaldo_otra.sql" <<SQL
USE master;
BACKUP DATABASE BancoAndino TO DISK = '${CARPETA_WIN}\\BancoAndino.bak'
    WITH INIT, FORMAT, COMPRESSION, CHECKSUM,
         ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = CertBancoAndino);
SQL

( cd "$RAIZ" && sqlcmd -S localhost -b -i .tmp/respaldo_otra.sql )
ls -la "$CARPETA"

# -y 0: sin limite de ancho; por defecto sqlcmd corta los tipos
# variables en 256 caracteres y el certificado no cabe.
CERT_HEX="$(sqlcmd -S localhost -d master -y 0 -Q \
  "SET NOCOUNT ON; SELECT CONVERT(varchar(max), CERTENCODED(CERT_ID('CertBancoAndino')), 2) AS hex;" \
  | grep -oE '[0-9A-F]{20,}' | head -1)"
PVK_HEX="$(sqlcmd -S localhost -d master -y 0 -Q \
  "SET NOCOUNT ON; SELECT CONVERT(varchar(max), CERTPRIVATEKEY(CERT_ID('CertBancoAndino'), '${CLAVE_CERT}'), 2) AS hex;" \
  | grep -oE '[0-9A-F]{20,}' | head -1)"

if [ -z "$CERT_HEX" ] || [ -z "$PVK_HEX" ]; then
  echo "No se pudo exportar el certificado TDE"; exit 1
fi
echo "   certificado ${#CERT_HEX} caracteres hex, clave privada ${#PVK_HEX} caracteres hex"

echo "== 2/5 Instancia limpia en contenedor"
docker rm -f "$CONTENEDOR" >/dev/null 2>&1 || true
docker run -d --name "$CONTENEDOR" \
  -e ACCEPT_EULA=Y \
  -e MSSQL_SA_PASSWORD="$SA_PASS" \
  -e MSSQL_PID=Developer \
  -p "${PUERTO}:1433" \
  mcr.microsoft.com/mssql/server:2022-latest >/dev/null

# MSYS2_ARG_CONV_EXCL evita que Git Bash convierta /opt/... en una ruta de Windows.
for i in $(seq 1 60); do
  if MSYS2_ARG_CONV_EXCL='*' docker exec "$CONTENEDOR" "$SQLCMD_CONTENEDOR" -S localhost -U sa -P "$SA_PASS" -C -Q "SELECT 1" >/dev/null 2>&1; then
    echo "   motor listo"
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    echo "   el motor no respondio"; docker logs "$CONTENEDOR" | tail -30; exit 1
  fi
done

echo "== 3/5 Copia del backup al contenedor"
MSYS2_ARG_CONV_EXCL='*' docker exec "$CONTENEDOR" mkdir -p /tmp/banco
docker cp "$CARPETA/BancoAndino.bak" "$CONTENEDOR:/tmp/banco/"
MSYS2_ARG_CONV_EXCL='*' docker exec "$CONTENEDOR" ls -la /tmp/banco

echo "== 4/5 Certificado, SMK propia y restauracion en la instancia nueva"
cat > "$RAIZ/.tmp/restaurar_otra.sql" <<SQL
USE master;
-- La instancia nueva no tiene DMK: hace falta para proteger la clave
-- privada del certificado importado (su SMK es propia y ya existe).
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'DMK_Otra_Instancia_2026!';

CREATE CERTIFICATE CertBancoAndino FROM BINARY = 0x${CERT_HEX}
    WITH PRIVATE KEY (
        BINARY = 0x${PVK_HEX},
        DECRYPTION BY PASSWORD = '${CLAVE_CERT}'
    );

RESTORE VERIFYONLY FROM DISK = '/tmp/banco/BancoAndino.bak' WITH CHECKSUM;

RESTORE DATABASE BancoAndino_Otra FROM DISK = '/tmp/banco/BancoAndino.bak'
WITH MOVE 'BancoAndino'     TO '/var/opt/mssql/data/BancoAndino_Otra.mdf',
     MOVE 'BancoAndino_log' TO '/var/opt/mssql/data/BancoAndino_Otra_log.ldf',
     REPLACE, RECOVERY;
SQL

MSYS2_ARG_CONV_EXCL='*' docker exec -i "$CONTENEDOR" "$SQLCMD_CONTENEDOR" \
  -S localhost -U sa -P "$SA_PASS" -C -b < "$RAIZ/.tmp/restaurar_otra.sql"

echo "== 5/5 Verificacion"
MSYS2_ARG_CONV_EXCL='*' docker exec -i "$CONTENEDOR" "$SQLCMD_CONTENEDOR" \
  -S localhost -U sa -P "$SA_PASS" -C -b -W -s '|' <<'SQL'
SET NOCOUNT ON;
-- El certificado quedo protegido por la SMK de ESTA instancia.
SELECT name AS certificado, pvt_key_encryption_type_desc AS clave_privada
FROM master.sys.certificates WHERE name = 'CertBancoAndino';

SELECT DB_NAME(dek.database_id) AS base, dek.encryption_state_desc AS estado,
       dek.key_algorithm AS algoritmo, dek.key_length AS longitud
FROM sys.dm_database_encryption_keys dek
WHERE dek.database_id = DB_ID('BancoAndino_Otra');

DBCC CHECKDB('BancoAndino_Otra') WITH NO_INFOMSGS;

USE BancoAndino_Otra;
SELECT 'Clientes' AS tabla, COUNT(*) AS filas FROM dbo.Clientes
UNION ALL SELECT 'Transacciones', COUNT(*) FROM dbo.Transacciones
UNION ALL SELECT 'Empleados', COUNT(*) FROM dbo.Empleados
UNION ALL SELECT 'TarjetasCifradas', COUNT(*) FROM dbo.TarjetasCifradas
UNION ALL SELECT 'ClientesAE', COUNT(*) FROM dbo.ClientesAE;

SELECT DocID, FirmaValida, Integridad FROM dbo.vw_EstadoFirmas;

-- Always Encrypted: en la instancia nueva y sin la CMK solo hay binario.
SELECT TOP 1 DATALENGTH(CI) AS bytes_ci, CONVERT(varchar(24), CI, 2) AS prefijo_hex
FROM dbo.ClientesAE;
SQL

echo ""
echo "Restauracion verificada en la instancia del contenedor $CONTENEDOR (puerto $PUERTO)."
echo "Para limpiar: docker rm -f $CONTENEDOR"
