#!/bin/bash
# Muestra el estado del servicio de monitoreo

cd "$(dirname "$0")"

if [ ! -f vm_monitor.pid ]; then
    echo "El monitor no está ejecutándose (no existe archivo PID)"
    exit 1
fi

PID=$(cat vm_monitor.pid)

if ! ps -p $PID > /dev/null 2>&1; then
    echo "El monitor no está ejecutándose (PID $PID no existe)"
    rm -f vm_monitor.pid
    exit 1
fi

echo "=== Estado del Monitor de VMs ==="
echo "PID: $PID"
echo "Tiempo de ejecución: $(ps -p $PID -o etime= | tr -d ' ')"
echo ""
echo "=== Últimas 10 líneas del log ==="
if [ -f vm_monitor.log ]; then
    tail -10 vm_monitor.log
else
    echo "No hay archivo de log"
fi
