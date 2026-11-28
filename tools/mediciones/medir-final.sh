#!/usr/bin/env bash
# Medicion final: un solo indice filtrado de vigentes y dos borrados.
set -u
cd "$(dirname "$0")"
LOG=medicion-final.log

# Aborta antes de tocar SesionesApp si el login no tiene DDL: el arnes hace
# TRUNCATE TABLE, CREATE/DROP INDEX y UPDATE STATISTICS. app_bancoandino no alcanza.
exigir_permisos() {
    local salida estado
    salida=$(MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -h -1 -I -i 00_verificar_permisos.sql 2>&1)
    estado=$?
    if [ "$estado" -ne 0 ]; then
        printf '%s\n' "$salida" | sed '/Changed database context/d; /^$/d; s/\r$//'
        echo "ABORTA: dbo.SesionesApp quedo intacta. Usa un login sysadmin o dbo." >&2
        exit 1
    fi
}

exigir_permisos
: > "$LOG"

run() { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -I -i "$1" >>"$LOG" 2>&1; }
q()   { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -h -1 -I -Q "$1" >>"$LOG" 2>&1; }
section() { echo "=== $* ===" >>"$LOG"; }

section "quitar el indice por Creada y recrear los procedimientos"
q "IF EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.SesionesApp') AND name = 'IX_SesionesApp_Vigentes_Creada') DROP INDEX IX_SesionesApp_Vigentes_Creada ON dbo.SesionesApp;"
run ../../app/sql/17_sesiones.sql

section "D validar con Uso"; run 00_preparar.sql; run 08_validar.sql
section "D login sin muertas"; run 02_login.sql
section "D login con 2.000 muertas"; run 00_preparar.sql; run 03_muertas.sql; run 04_login_muertas.sql
section "D comportamiento de la caducidad absoluta"; run 00_preparar.sql; run 03_muertas.sql; run 10_final.sql

section "restaurar sesiones reales"; run 05_restaurar.sql
q "SELECT name FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.SesionesApp') AND name LIKE 'IX%';"

grep -E '^(===)|logical reads|^resumen |filas_restantes|vencidas|Msg [0-9]|^IX_Sesiones|sesiones_restauradas' "$LOG" \
  | sed -E "s/Table 'SesionesApp'\. Scan count [0-9]+, //; s/, physical reads.*//"
