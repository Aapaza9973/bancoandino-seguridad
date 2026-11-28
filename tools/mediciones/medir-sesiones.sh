#!/usr/bin/env bash
# Medicion del barrido del login y del camino caliente de la sesion.
# Dos escenarios reales del diseno final de 17_sesiones.sql:
#   A) con el indice filtrado IX_SesionesApp_Vigentes_Uso
#   B) sin indices de vigentes (linea base)
set -u
cd "$(dirname "$0")"
LOG=medicion.log
: > "$LOG"

run() { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -I -i "$1" >>"$LOG" 2>&1; }
q()   { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -h -1 -I -Q "$1" >>"$LOG" 2>&1; }
section() { echo "=== $* ===" >>"$LOG"; }

section "0) aplicar el diseno final de 17_sesiones.sql"
run ../../app/sql/17_sesiones.sql

section "A) con IX_SesionesApp_Vigentes_Uso"
run 00_preparar.sql
section "A validar"; run 01_validar.sql
section "A login sin muertas"; run 02_login.sql
section "A login con 2.000 muertas"; run 00_preparar.sql; run 03_muertas.sql; run 04_login_muertas.sql

section "B) sin indices de vigentes (linea base)"
q "IF EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.SesionesApp') AND name = 'IX_SesionesApp_Vigentes_Uso') DROP INDEX IX_SesionesApp_Vigentes_Uso ON dbo.SesionesApp;"
run 00_preparar.sql
section "B validar"; run 01_validar.sql
section "B login sin muertas"; run 02_login.sql
section "B login con 2.000 muertas"; run 00_preparar.sql; run 03_muertas.sql; run 04_login_muertas.sql

section "reaplicar 17_sesiones.sql y restaurar las sesiones reales"
run ../../app/sql/17_sesiones.sql
run 05_restaurar.sql
q "SELECT name FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.SesionesApp') AND name LIKE 'IX%';"

grep -E '^(===|---)|logical reads|^resumen |filas_cargadas|filas_restantes|vencidas|Msg [0-9]|^IX_Sesiones|sesiones_restauradas' "$LOG" \
  | sed -E "s/Table 'SesionesApp'\. Scan count [0-9]+, //; s/, physical reads.*//"
