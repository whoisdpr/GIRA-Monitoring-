#!/usr/bin/env python3
"""
Parallel Monitor - Sistema de monitoreo paralelo para VM Monitor

Este módulo proporciona:
- Procesamiento paralelo de workers
- Optimización de comandos SSH
- Control de concurrencia y recursos
- Pool de conexiones gestionado
- Recolección optimizada de métricas
"""

import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from queue import Queue, Empty
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict

@dataclass
class WorkerMetrics:
    """Métricas de un worker individual"""
    worker_name: str
    vms_data: Dict[str, Dict[str, Any]]
    collection_time: float
    error_count: int
    status: str  # 'success', 'partial', 'failed'
    timestamp: datetime

@dataclass
class MonitoringCycle:
    """Resultado de un ciclo completo de monitoreo"""
    cycle_id: int
    start_time: datetime
    end_time: datetime
    duration: float
    total_vms: int
    worker_results: Dict[str, WorkerMetrics]
    errors: List[str]
    success_rate: float

class ParallelResourceManager:
    """Gestor de recursos para operaciones paralelas"""
    
    def __init__(self, max_workers: int = 7, max_debouncing: int = 3, max_ssh_per_worker: int = 2):
        """
        Inicializa el gestor de recursos
        
        Args:
            max_workers: Máximo número de workers a procesar en paralelo
            max_debouncing: Máximo número de procesos de debouncing simultáneos
            max_ssh_per_worker: Máximo conexiones SSH por worker
        """
        self.max_workers = max_workers
        self.max_debouncing = max_debouncing
        self.max_ssh_per_worker = max_ssh_per_worker
        
        # Semáforos para control de concurrencia
        self.debouncing_semaphore = threading.Semaphore(max_debouncing)
        self.worker_semaphores = defaultdict(lambda: threading.Semaphore(max_ssh_per_worker))
        
        # Pool de threads principal
        self.main_executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ParallelMonitor")
        
        # Pool secundario para operaciones auxiliares
        self.aux_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="AuxOperations")
        
        # Estadísticas
        self.active_operations = defaultdict(int)
        self.resource_usage_history = []
        
        self.logger = logging.getLogger('parallel_resource_manager')
    
    def acquire_debouncing_slot(self, timeout: float = 5.0) -> bool:
        """
        Adquiere slot para proceso de debouncing
        
        Args:
            timeout: Tiempo máximo de espera
            
        Returns:
            True si se adquirió el slot exitosamente
        """
        acquired = self.debouncing_semaphore.acquire(timeout=timeout)
        if acquired:
            self.active_operations['debouncing'] += 1
            self.logger.debug("🟡 Slot de debouncing adquirido")
        else:
            self.logger.warning("⏸️ Timeout esperando slot de debouncing")
        return acquired
    
    def release_debouncing_slot(self):
        """Libera slot de debouncing"""
        self.debouncing_semaphore.release()
        self.active_operations['debouncing'] = max(0, self.active_operations['debouncing'] - 1)
        self.logger.debug("🟢 Slot de debouncing liberado")
    
    def acquire_worker_slot(self, worker: str, timeout: float = 10.0) -> bool:
        """
        Adquiere slot SSH para worker específico
        
        Args:
            worker: Nombre del worker
            timeout: Tiempo máximo de espera
            
        Returns:
            True si se adquirió el slot exitosamente
        """
        acquired = self.worker_semaphores[worker].acquire(timeout=timeout)
        if acquired:
            self.active_operations[f'ssh_{worker}'] += 1
            self.logger.debug(f"🔗 Slot SSH adquirido para {worker}")
        else:
            self.logger.warning(f"⏸️ Timeout esperando slot SSH para {worker}")
        return acquired
    
    def release_worker_slot(self, worker: str):
        """Libera slot SSH para worker"""
        self.worker_semaphores[worker].release()
        key = f'ssh_{worker}'
        self.active_operations[key] = max(0, self.active_operations[key] - 1)
        self.logger.debug(f"🔗 Slot SSH liberado para {worker}")
    
    def get_resource_usage(self) -> Dict[str, Any]:
        """Obtiene estadísticas de uso de recursos"""
        return {
            'active_debouncing': self.active_operations['debouncing'],
            'active_ssh_connections': sum(v for k, v in self.active_operations.items() if k.startswith('ssh_')),
            'available_debouncing_slots': self.debouncing_semaphore._value,
            'total_active_operations': sum(self.active_operations.values()),
            'timestamp': datetime.now()
        }
    
    def shutdown(self):
        """Cierra los pools de threads"""
        self.logger.info("🔄 Cerrando pools de threads...")
        self.main_executor.shutdown(wait=True)
        self.aux_executor.shutdown(wait=True)
        self.logger.info("✅ Pools de threads cerrados")

class OptimizedSSHCollector:
    """Recolector optimizado de métricas via SSH"""
    
    def __init__(self, resource_manager: ParallelResourceManager):
        """
        Inicializa el recolector optimizado
        
        Args:
            resource_manager: Gestor de recursos
        """
        self.resource_manager = resource_manager
        self.logger = logging.getLogger('optimized_ssh_collector')
    
    def collect_all_vm_metrics(self, worker: str, ssh_manager) -> Dict[str, Any]:
        """
        Recolecta todas las métricas de VMs en un worker con un solo comando SSH optimizado
        
        Args:
            worker: Nombre del worker
            ssh_manager: Gestor SSH resiliente
            
        Returns:
            Diccionario con métricas de todas las VMs
        """
        # Adquirir slot para este worker
        if not self.resource_manager.acquire_worker_slot(worker, timeout=15):
            self.logger.error(f"❌ No se pudo adquirir slot SSH para {worker}")
            return {}
        
        try:
            return self._execute_optimized_collection(worker, ssh_manager)
        except Exception as e:
            self.logger.error(f"Error en collect_all_vm_metrics para {worker}: {e}")
            return {}
        finally:
            self.resource_manager.release_worker_slot(worker)
    
    def _execute_optimized_collection(self, worker: str, ssh_manager) -> Dict[str, Any]:
        """Ejecuta la recolección optimizada"""
        
        # Script ultra-optimizado que recolecta TODO en una sola conexión SSH
        optimized_script = """
        # Obtener timestamp inicial
        echo "COLLECTION_START:$(date +%s)"
        
        # Obtener información de sistema para contexto
        echo "SYSTEM_LOAD:$(cat /proc/loadavg | awk '{print $1, $2, $3}')"
        echo "SYSTEM_MEMORY:$(free -m | awk '/Mem:/ {print $2, $3, $4}')"
        
        # Listar VMs activas - FILTRAR ERRORES DE SETLOCALE
        vms=$(sudo virsh list --name 2>/dev/null | grep -v '^$' | grep -v 'setlocale' | grep -v 'error' | grep -v 'Error')
        vm_count=$(echo "$vms" | wc -l)
        echo "VM_COUNT:$vm_count"
        
        # Si no hay VMs, salir temprano
        [ $vm_count -eq 0 ] && echo "NO_VMS_FOUND" && exit 0
        
        # Procesar cada VM de forma eficiente
        for vm in $vms; do
            echo "=== VM_START:$vm ==="
            
            # 1. Obtener PID del proceso QEMU
            qemu_pid=$(ps aux | grep "qemu.*$vm" | grep -v grep | awk '{print $2}' | head -1)
            
            if [ -z "$qemu_pid" ]; then
                echo "ERROR:NO_QEMU_PROCESS"
                echo "=== VM_END:$vm ==="
                continue
            fi
            
            echo "QEMU_PID:$qemu_pid"
            
            # 2. CPU - Método optimizado con una sola pausa
            if [ -f "/proc/$qemu_pid/stat" ]; then
                # Lectura inicial
                read utime1 stime1 cutime1 cstime1 < <(awk '{print $14, $15, $16, $17}' /proc/$qemu_pid/stat 2>/dev/null)
                read cpu_total1 < <(awk '{print $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
                
                # Breve pausa (0.5 segundos para más rapidez)
                sleep 0.5
                
                # Lectura final
                read utime2 stime2 cutime2 cstime2 < <(awk '{print $14, $15, $16, $17}' /proc/$qemu_pid/stat 2>/dev/null)
                read cpu_total2 < <(awk '{print $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
                
                if [ -n "$utime2" ] && [ -n "$cpu_total2" ]; then
                    # Calcular CPU usage más preciso
                    process_ticks=$(echo "($utime2 - $utime1) + ($stime2 - $stime1)" | bc 2>/dev/null || echo "0")
                    system_ticks=$(echo "$cpu_total2 - $cpu_total1" | bc 2>/dev/null || echo "1")
                    
                    if [ "$system_ticks" -gt 0 ]; then
                        cpu_percent=$(echo "scale=2; ($process_ticks * 100 * 2) / $system_ticks" | bc 2>/dev/null || echo "0")
                        echo "CPU_PERCENT:$cpu_percent"
                    else
                        echo "CPU_PERCENT:0"
                    fi
                fi
            fi
            
            # 3. Memoria del proceso (RSS, VSZ, etc.)
            if [ -f "/proc/$qemu_pid/status" ]; then
                memory_info=$(awk '/^(VmRSS|VmSize|VmPeak|VmHWM):/ {print $1 $2}' /proc/$qemu_pid/status 2>/dev/null | tr '\n' ' ')
                echo "MEMORY_INFO:$memory_info"
            fi
            
            # 4. Threads y contexto del proceso
            if [ -f "/proc/$qemu_pid/stat" ]; then
                read threads state priority nice < <(awk '{print $20, $3, $18, $19}' /proc/$qemu_pid/stat 2>/dev/null)
                echo "PROCESS_INFO:threads=$threads state=$state priority=$priority nice=$nice"
            fi
            
            # 5. I/O del proceso (si está disponible)
            if [ -f "/proc/$qemu_pid/io" ]; then
                io_info=$(awk '/^(read_bytes|write_bytes|syscr|syscw):/ {printf "%s=%s ", $1, $2}' /proc/$qemu_pid/io 2>/dev/null)
                echo "IO_INFO:$io_info"
            fi
            
            # 6. Información de virsh (metadatos)
            virsh_info=$(timeout 5 sudo virsh dumpxml "$vm" 2>/dev/null | awk '
                BEGIN { vcpus=1; memory=0; name=""; project=""; flavor="" }
                /<vcpu/ { match($0, />([^<]*)</, arr); vcpus=arr[1]; if(vcpus=="") vcpus=1 }
                /<memory.*KiB/ { match($0, />([^<]*)</, arr); memory=arr[1]; if(memory=="") memory=0 }
                /<nova:name/ { match($0, />([^<]*)</, arr); name=arr[1] }
                /<nova:project/ { match($0, />([^<]*)</, arr); project=arr[1] }
                /<nova:flavor.*name="([^"]*)"/ { match($0, /name="([^"]*)"/, arr); flavor=arr[1] }
                END { 
                    printf "vcpus=%s memory_kb=%s display_name=%s project=%s flavor=%s", 
                           (vcpus ? vcpus : 1), (memory ? memory : 0), (name ? name : "'$vm'"), 
                           (project ? project : "Unknown"), (flavor ? flavor : "Unknown")
                }
            ')
            echo "VIRSH_INFO:$virsh_info"
            
            # 7. Estado de la VM
            vm_state=$(timeout 3 sudo virsh domstate "$vm" 2>/dev/null || echo "unknown")
            echo "VM_STATE:$vm_state"
            
            echo "=== VM_END:$vm ==="
        done
        
        echo "COLLECTION_END:$(date +%s)"
        """
        
        start_time = time.time()
        self.logger.debug(f"🚀 Iniciando recolección optimizada en {worker}")
        
        # Ejecutar script optimizado con timeout extendido
        output = ssh_manager.execute_command(worker, optimized_script, timeout=120)
        
        collection_time = time.time() - start_time
        
        if not output:
            self.logger.error(f"❌ Sin salida de {worker}")
            return {}
        
        # Parsear salida optimizada
        parsed_data = self._parse_optimized_output(output, worker, collection_time)
        
        self.logger.info(f"✅ Recolección {worker}: {len(parsed_data.get('vms', {}))} VMs en {collection_time:.1f}s")
        
        return parsed_data
    
    def _parse_optimized_output(self, output: str, worker: str, collection_time: float) -> Dict[str, Any]:
        """Parsea la salida del script optimizado"""
        
        result = {
            'worker': worker,
            'collection_time': collection_time,
            'timestamp': datetime.now(),
            'vms': {},
            'system_info': {},
            'errors': []
        }
        
        current_vm = None
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            try:
                # Fin de VM
                if line.startswith('=== VM_END:'):
                    current_vm = None
                    continue
                
                # Inicio de VM - puede ser "=== VM_START:nombre ===" o "VM_START:nombre"
                if '=== VM_START:' in line or line.startswith('VM_START:'):
                    # Extraer el nombre de VM
                    if '=== VM_START:' in line:
                        vm_name = line.split('=== VM_START:')[1].split(' ===')[0]
                    else:
                        vm_name = line.split('VM_START:', 1)[1]
                    
                    current_vm = vm_name
                    result['vms'][current_vm] = {
                        'vm_name': current_vm,
                        'worker': worker,
                        'metrics': {},
                        'errors': []
                    }
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    
                    # Información del sistema
                    if key == 'SYSTEM_LOAD':
                        load_values = value.split()
                        if len(load_values) >= 3:
                            result['system_info']['load'] = {
                                '1min': float(load_values[0]),
                                '5min': float(load_values[1]),
                                '15min': float(load_values[2])
                            }
                    
                    elif key == 'SYSTEM_MEMORY':
                        mem_values = value.split()
                        if len(mem_values) >= 3:
                            result['system_info']['memory'] = {
                                'total_mb': int(mem_values[0]),
                                'used_mb': int(mem_values[1]),
                                'free_mb': int(mem_values[2])
                            }
                    
                    elif key == 'VM_COUNT':
                        result['vm_count'] = int(value)
                    
                    # Datos de VM actual
                    elif current_vm and key in ['CPU_PERCENT', 'QEMU_PID']:
                        result['vms'][current_vm]['metrics'][key.lower()] = float(value) if key == 'CPU_PERCENT' else int(value)
                    
                    elif current_vm and key == 'MEMORY_INFO':
                        # Parsear información de memoria
                        mem_data = {}
                        for item in value.split():
                            if '=' in item:
                                mem_key, mem_val = item.split('=', 1)
                                try:
                                    mem_data[mem_key.lower()] = int(mem_val)
                                except:
                                    mem_data[mem_key.lower()] = mem_val
                        result['vms'][current_vm]['metrics']['memory'] = mem_data
                    
                    elif current_vm and key == 'PROCESS_INFO':
                        # Parsear información del proceso
                        proc_data = {}
                        for item in value.split():
                            if '=' in item:
                                proc_key, proc_val = item.split('=', 1)
                                try:
                                    proc_data[proc_key] = int(proc_val)
                                except:
                                    proc_data[proc_key] = proc_val
                        result['vms'][current_vm]['metrics']['process'] = proc_data
                    
                    elif current_vm and key == 'IO_INFO':
                        # Parsear información de I/O
                        io_data = {}
                        for item in value.split():
                            if '=' in item:
                                io_key, io_val = item.split('=', 1)
                                try:
                                    io_data[io_key.replace(':', '')] = int(io_val)
                                except:
                                    io_data[io_key.replace(':', '')] = io_val
                        result['vms'][current_vm]['metrics']['io'] = io_data
                    
                    elif current_vm and key == 'VIRSH_INFO':
                        # Parsear metadatos de virsh
                        virsh_data = {}
                        for item in value.split():
                            if '=' in item:
                                virsh_key, virsh_val = item.split('=', 1)
                                if virsh_key in ['vcpus', 'memory_kb']:
                                    try:
                                        virsh_data[virsh_key] = int(virsh_val)
                                    except:
                                        virsh_data[virsh_key] = 1 if virsh_key == 'vcpus' else 0
                                else:
                                    virsh_data[virsh_key] = virsh_val
                        result['vms'][current_vm]['metrics']['virsh'] = virsh_data
                    
                    elif current_vm and key == 'VM_STATE':
                        result['vms'][current_vm]['metrics']['state'] = value
                    
                    elif current_vm and key == 'ERROR':
                        result['vms'][current_vm]['errors'].append(value)
            
            except Exception as e:
                if current_vm:
                    result['vms'][current_vm]['errors'].append(f"Parse error: {e}")
                else:
                    result['errors'].append(f"Parse error for line '{line}': {e}")
        
        return result

class ParallelMonitor:
    """Monitor principal que coordina el procesamiento paralelo"""
    
    def __init__(self, workers: List[str], ssh_manager, max_workers: int = 7):
        """
        Inicializa el monitor paralelo
        
        Args:
            workers: Lista de workers a monitorear
            ssh_manager: Gestor SSH resiliente
            max_workers: Máximo workers en paralelo
        """
        self.workers = workers
        self.ssh_manager = ssh_manager
        self.max_workers = max_workers
        
        # Componentes
        self.resource_manager = ParallelResourceManager(max_workers)
        self.ssh_collector = OptimizedSSHCollector(self.resource_manager)
        
        # Estado
        self.cycle_counter = 0
        self.monitoring_history = []
        
        self.logger = logging.getLogger('parallel_monitor')
    
    def execute_monitoring_cycle(self) -> MonitoringCycle:
        """
        Ejecuta un ciclo completo de monitoreo en paralelo
        
        Returns:
            Resultado del ciclo de monitoreo
        """
        self.cycle_counter += 1
        start_time = datetime.now()
        
        self.logger.info(f"🔄 Iniciando ciclo paralelo #{self.cycle_counter}")
        
        # Enviar trabajos a pool de threads
        future_to_worker = {}
        
        with self.resource_manager.main_executor as executor:
            # Lanzar recolección paralela para cada worker
            for worker in self.workers:
                future = executor.submit(
                    self._monitor_single_worker, 
                    worker, 
                    self.cycle_counter
                )
                future_to_worker[future] = worker
            
            # Recoger resultados conforme se completan
            worker_results = {}
            errors = []
            total_vms = 0
            
            for future in as_completed(future_to_worker, timeout=180):  # 3 minutos máximo
                worker = future_to_worker[future]
                
                try:
                    worker_metrics = future.result()
                    worker_results[worker] = worker_metrics
                    total_vms += len(worker_metrics.vms_data)
                    
                    self.logger.info(f"✅ {worker}: {len(worker_metrics.vms_data)} VMs en {worker_metrics.collection_time:.1f}s")
                    
                except Exception as e:
                    error_msg = f"Error en {worker}: {e}"
                    errors.append(error_msg)
                    self.logger.error(f"❌ {error_msg}")
                    
                    # Crear métrica de error
                    worker_results[worker] = WorkerMetrics(
                        worker_name=worker,
                        vms_data={},
                        collection_time=0.0,
                        error_count=1,
                        status='failed',
                        timestamp=datetime.now()
                    )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Calcular tasa de éxito
        successful_workers = sum(1 for wm in worker_results.values() if wm.status == 'success')
        success_rate = successful_workers / len(self.workers) if self.workers else 0
        
        # Crear resultado del ciclo
        cycle_result = MonitoringCycle(
            cycle_id=self.cycle_counter,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            total_vms=total_vms,
            worker_results=worker_results,
            errors=errors,
            success_rate=success_rate
        )
        
        # Guardar en histórico
        self.monitoring_history.append(cycle_result)
        if len(self.monitoring_history) > 50:  # Mantener últimos 50 ciclos
            self.monitoring_history.pop(0)
        
        self.logger.info(f"🎯 Ciclo #{self.cycle_counter} completado: "
                        f"{total_vms} VMs, {duration:.1f}s, {success_rate:.1%} éxito")
        
        return cycle_result
    
    def _monitor_single_worker(self, worker: str, cycle_id: int) -> WorkerMetrics:
        """Monitorea un worker individual"""
        start_time = time.time()
        
        try:
            # Recolectar métricas optimizadas
            raw_data = self.ssh_collector.collect_all_vm_metrics(worker, self.ssh_manager)
            
            if not raw_data or not raw_data.get('vms'):
                return WorkerMetrics(
                    worker_name=worker,
                    vms_data={},
                    collection_time=time.time() - start_time,
                    error_count=1,
                    status='failed',
                    timestamp=datetime.now()
                )
            
            # Procesar datos de VMs
            processed_vms = {}
            error_count = 0
            
            for vm_name, vm_data in raw_data['vms'].items():
                try:
                    # Extraer métricas clave
                    metrics = vm_data.get('metrics', {})
                    
                    processed_vm = {
                        'vm_name': vm_name,
                        'worker': worker,
                        'cpu_percent': metrics.get('cpu_percent', 0.0),
                        'vcpus': metrics.get('virsh', {}).get('vcpus', 1),
                        'memory_kb': metrics.get('virsh', {}).get('memory_kb', 0),
                        'display_name': metrics.get('virsh', {}).get('display_name', vm_name),
                        'project': metrics.get('virsh', {}).get('project', 'Unknown'),
                        'flavor': metrics.get('virsh', {}).get('flavor', 'Unknown'),
                        'state': metrics.get('state', 'unknown'),
                        'qemu_pid': metrics.get('qemu_pid', 0),
                        'process_info': metrics.get('process', {}),
                        'memory_info': metrics.get('memory', {}),
                        'io_info': metrics.get('io', {}),
                        'errors': vm_data.get('errors', [])
                    }
                    
                    if processed_vm['errors']:
                        error_count += 1
                    
                    processed_vms[vm_name] = processed_vm
                    
                except Exception as e:
                    error_count += 1
                    self.logger.warning(f"⚠️ Error procesando {vm_name} en {worker}: {e}")
            
            collection_time = time.time() - start_time
            status = 'success' if error_count == 0 else 'partial' if processed_vms else 'failed'
            
            return WorkerMetrics(
                worker_name=worker,
                vms_data=processed_vms,
                collection_time=collection_time,
                error_count=error_count,
                status=status,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self.logger.error(f"❌ Error crítico monitoreando {worker}: {e}")
            return WorkerMetrics(
                worker_name=worker,
                vms_data={},
                collection_time=time.time() - start_time,
                error_count=1,
                status='failed',
                timestamp=datetime.now()
            )
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de performance"""
        if not self.monitoring_history:
            return {}
        
        recent_cycles = self.monitoring_history[-10:]  # Últimos 10 ciclos
        
        durations = [c.duration for c in recent_cycles]
        total_vms = [c.total_vms for c in recent_cycles]
        success_rates = [c.success_rate for c in recent_cycles]
        
        return {
            'cycles_completed': len(self.monitoring_history),
            'recent_performance': {
                'avg_duration': sum(durations) / len(durations),
                'min_duration': min(durations),
                'max_duration': max(durations),
                'avg_vms_per_cycle': sum(total_vms) / len(total_vms),
                'avg_success_rate': sum(success_rates) / len(success_rates),
            },
            'resource_usage': self.resource_manager.get_resource_usage(),
            'last_cycle': recent_cycles[-1] if recent_cycles else None
        }
    
    def shutdown(self):
        """Cierra el monitor paralelo"""
        self.logger.info("🔄 Cerrando monitor paralelo...")
        self.resource_manager.shutdown()
        self.logger.info("✅ Monitor paralelo cerrado")


if __name__ == "__main__":
    # Demo del sistema paralelo
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    print("⚡ DEMO DEL SISTEMA DE MONITOREO PARALELO")
    print("=" * 45)
    
    # Mock SSH manager para demo
    class MockSSHManager:
        def execute_command(self, worker, command, timeout=None):
            import random
            time.sleep(random.uniform(0.5, 2.0))  # Simular latencia variable
            return f"VM_COUNT:5\n=== VM_START:vm1 ===\nCPU_PERCENT:45.2\n=== VM_END:vm1 ==="
    
    # Crear monitor paralelo
    workers = ["hast-wn1", "hast-wn2", "hast-wn3"]
    mock_ssh = MockSSHManager()
    
    parallel_monitor = ParallelMonitor(workers, mock_ssh, max_workers=3)
    
    try:
        # Ejecutar ciclo de prueba
        print("🚀 Ejecutando ciclo de monitoreo paralelo...")
        cycle_result = parallel_monitor.execute_monitoring_cycle()
        
        print(f"✅ Ciclo completado en {cycle_result.duration:.1f}s")
        print(f"📊 VMs totales: {cycle_result.total_vms}")
        print(f"🎯 Tasa de éxito: {cycle_result.success_rate:.1%}")
        
        # Mostrar estadísticas
        stats = parallel_monitor.get_performance_stats()
        print(f"📈 Estadísticas: {stats}")
        
    finally:
        parallel_monitor.shutdown()
    
    print("🎉 Demo completado")