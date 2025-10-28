#!/bin/bash
# Detiene el monitoreo de VMs

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

echo "Deteniendo vm-monitoring (PID: $PID)..."
kill $PID

# Espera hasta 10 segundos para que termine
for i in {1..10}; do
    if ! ps -p $PID > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Si sigue vivo, fuerza la terminación
if ps -p $PID > /dev/null 2>&1; then
    echo "Forzando detención..."
    kill -9 $PID
fi

rm -f vm_monitor.pid
echo "Monitor detenido"
