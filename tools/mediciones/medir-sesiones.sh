#!/usr/bin/env bash
# Medicion del barrido del login y del camino caliente de la sesion.
set -u
cd "$(dirname "$0")"
LOG=medicion.log
: > "$LOG"

run() { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -I -i "$1" >>"$LOG" 2>&1; }
q()   { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -h -1 -I -Q "$1" >>"$LOG" 2>&1; }
section() { echo "=== $* ===" >>"$LOG"; }

quitar() { q "IF EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.SesionesApp') AND name = '$1') DROP INDEX $1 ON dbo.SesionesApp;"; }
poner()  { q "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.SesionesApp') AND name = '$1') CREATE NONCLUSTERED INDEX $1 ON dbo.SesionesApp ($2) WHERE Revocada = $3;"; }

section "A) Uso + Creada + Revocadas (estado del arbol de trabajo)"
run 00_preparar.sql
section "A validar"; run 01_validar.sql
section "A login sin muertas"; run 02_login.sql
section "A login con 2.000 muertas"; run 00_preparar.sql; run 03_muertas.sql; run 04_login_muertas.sql

section "B) Uso + Revocadas: el DELETE por Creada sin su indice"
quitar IX_SesionesApp_Vigentes_Creada
run 00_preparar.sql
section "B validar"; run 01_validar.sql
section "B login sin muertas"; run 02_login.sql
section "B login con 2.000 muertas"; run 00_preparar.sql; run 03_muertas.sql; run 04_login_muertas.sql

section "C) solo Revocadas: sin indices de vigentes (linea base)"
quitar IX_SesionesApp_Vigentes_Uso
run 00_preparar.sql
section "C validar"; run 01_validar.sql
section "C login sin muertas"; run 02_login.sql
section "C login con 2.000 muertas"; run 00_preparar.sql; run 03_muertas.sql; run 04_login_muertas.sql

section "restaurar Uso y las sesiones reales"
poner IX_SesionesApp_Vigentes_Uso UltimoUso 0
run 05_restaurar.sql

grep -E '^(===|---)|logical reads|^resumen |filas_cargadas|filas_restantes|vencidas|Msg [0-9]|^IX_Sesiones' "$LOG" \
  | sed -E "s/Table 'SesionesApp'\. Scan count [0-9]+, //; s/, physical reads.*//"
