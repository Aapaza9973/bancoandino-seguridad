#!/usr/bin/env bash
# Compara el camino caliente sin ningun indice filtrado y explica el plan.
set -u
cd "$(dirname "$0")"
LOG=medicion-plan.log

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
