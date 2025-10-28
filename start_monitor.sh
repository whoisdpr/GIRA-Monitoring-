#!/bin/bash
# Inicia el monitoreo de VMs

cd "$(dirname "$0")"

if [ -f vm_monitor.pid ]; then
    PID=$(cat vm_monitor.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo "El monitor ya está ejecutándose (PID: $PID)"
        exit 1
    fi
fi

echo "Iniciando vm-monitoring..."
nohup python3 monitor.py > /dev/null 2>&1 &
echo $! > vm_monitor.pid
echo "Monitor iniciado (PID: $(cat vm_monitor.pid))"
echo "Ver logs: tail -f vm_monitor.log"
