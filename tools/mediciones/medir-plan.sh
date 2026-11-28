#!/usr/bin/env bash
# Compara el camino caliente sin ningun indice filtrado y explica el plan.
set -u
cd "$(dirname "$0")"
LOG=medicion-plan.log
: > "$LOG"

run() { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -I -i "$1" >>"$LOG" 2>&1; }
q()   { MSYS2_ARG_CONV_EXCL='*' sqlcmd -S localhost -d BancoAndino -b -W -h -1 -I -Q "$1" >>"$LOG" 2>&1; }

echo "=== plan con Uso + Revocadas ===" >>"$LOG"
run 00_preparar.sql > /dev/null
run 07_plan.sql
echo "=== validar con Uso + Revocadas ===" >>"$LOG"
run 08_validar.sql

echo "=== sin ningun indice filtrado ===" >>"$LOG"
q "DROP INDEX IX_SesionesApp_Vigentes_Uso ON dbo.SesionesApp;"
q "DROP INDEX IX_SesionesApp_Revocadas ON dbo.SesionesApp;"
q "UPDATE STATISTICS dbo.SesionesApp;"
run 08_validar.sql
run 07_plan.sql

echo "=== restaurar indices y sesiones reales ===" >>"$LOG"
q "CREATE NONCLUSTERED INDEX IX_SesionesApp_Vigentes_Uso ON dbo.SesionesApp (UltimoUso) WHERE Revocada = 0;"
q "CREATE NONCLUSTERED INDEX IX_SesionesApp_Revocadas ON dbo.SesionesApp (Revocada) WHERE Revocada = 1;"
run 05_restaurar.sql

grep -E '^(===)|logical reads|plan_bytes|mantiene|actualiza|usa Index|sesiones_restauradas' "$LOG" \
  | sed -E "s/Table 'SesionesApp'\. Scan count [0-9]+, //; s/, physical reads.*//"
