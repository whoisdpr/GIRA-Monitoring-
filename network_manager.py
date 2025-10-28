#!/usr/bin/env python3
"""
Network Manager - Sistema de conectividad resiliente para VM Monitor

Este módulo proporciona:
- Verificación de conectividad antes de SSH
- Timeouts adaptativos basados en histórico
- Reintentos con backoff exponencial
- Recuperación automática ante fallos
"""

import socket
import time
import subprocess
import logging
from functools import wraps
from datetime import datetime, timedelta
from typing import Dict, Optional, Callable, Any

class NetworkManager:
    """Gestor de red resiliente para conexiones SSH"""
    
    def __init__(self, workers: list, max_retries: int = 3, base_timeout: int = 30):
        """
        Inicializa el gestor de red
        
        Args:
            workers: Lista de workers a monitorear
            max_retries: Número máximo de reintentos
            base_timeout: Timeout base en segundos
        """
        self.workers = workers
        self.max_retries = max_retries
        self.base_timeout = base_timeout
        
        # Estado de salud de cada worker
        self.worker_status = {worker: True for worker in workers}
        self.worker_performance = {worker: [] for worker in workers}  # Histórico de tiempos
        self.last_connectivity_check = {worker: None for worker in workers}
        
        # Configurar logger específico
        self.logger = logging.getLogger('network_manager')
        
    def check_connectivity(self, worker: str, port: int = 22) -> bool:
        """
        Verifica conectividad TCP básica antes de SSH
        
        Args:
            worker: Nombre del worker
            port: Puerto a verificar (default: 22 para SSH)
            
        Returns:
            True si la conectividad es exitosa
        """
        try:
            # Cache de conectividad (verificar cada 30 segundos máximo)
            now = datetime.now()
            last_check = self.last_connectivity_check.get(worker)
            
            if last_check and (now - last_check).total_seconds() < 30:
                return self.worker_status.get(worker, False)
            
            self.logger.debug(f"Verificando conectividad a {worker}:{port}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # Timeout corto para test de conectividad
            result = sock.connect_ex((worker, port))
            sock.close()
            
            is_connected = result == 0
            self.worker_status[worker] = is_connected
            self.last_connectivity_check[worker] = now
            
            if is_connected:
                self.logger.debug(f"✅ Conectividad OK: {worker}")
            else:
                self.logger.warning(f"❌ Conectividad FALLO: {worker}")
                
            return is_connected
            
        except Exception as e:
            self.logger.error(f"Error verificando conectividad {worker}: {e}")
            self.worker_status[worker] = False
            self.last_connectivity_check[worker] = now
            return False
    
    def get_adaptive_timeout(self, worker: str) -> int:
        """
        Calcula timeout adaptativo basado en histórico de performance
        
        Args:
            worker: Nombre del worker
            
        Returns:
            Timeout adaptativo en segundos
        """
        # Si no hay histórico o worker está marcado como problemático
        if not self.worker_status.get(worker, True):
            return self.base_timeout * 2
        
        # Calcular timeout basado en performance histórica
        performance_history = self.worker_performance.get(worker, [])
        
        if len(performance_history) >= 3:
            # Usar percentil 90 de los últimos tiempos + margen
            recent_times = performance_history[-10:]  # Últimas 10 mediciones
            avg_time = sum(recent_times) / len(recent_times)
            max_time = max(recent_times)
            
            # Timeout = tiempo promedio + 50% de margen, mínimo base_timeout
            adaptive_timeout = max(self.base_timeout, int(avg_time * 1.5))
            
            # Limitar timeout máximo
            return min(adaptive_timeout, self.base_timeout * 3)
        
        return self.base_timeout
    
    def record_operation_time(self, worker: str, operation_time: float):
        """
        Registra tiempo de operación para cálculos adaptativos
        
        Args:
            worker: Nombre del worker
            operation_time: Tiempo de la operación en segundos
        """
        if worker not in self.worker_performance:
            self.worker_performance[worker] = []
        
        # Mantener solo las últimas 20 mediciones
        self.worker_performance[worker].append(operation_time)
        if len(self.worker_performance[worker]) > 20:
            self.worker_performance[worker].pop(0)
    
    def retry_with_backoff(self, max_attempts: int = None) -> Callable:
        """
        Decorator para reintentos con backoff exponencial
        
        Args:
            max_attempts: Número máximo de intentos (usa self.max_retries si es None)
        """
        if max_attempts is None:
            max_attempts = self.max_retries
            
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                last_exception = None
                
                for attempt in range(max_attempts):
                    try:
                        self.logger.debug(f"Intento {attempt + 1}/{max_attempts} para {func.__name__}")
                        result = func(*args, **kwargs)
                        
                        if attempt > 0:
                            self.logger.info(f"✅ Éxito en intento {attempt + 1} para {func.__name__}")
                        
                        return result
                        
                    except Exception as e:
                        last_exception = e
                        
                        if attempt < max_attempts - 1:
                            # Backoff exponencial: 1s, 2s, 4s, 8s...
                            wait_time = 2 ** attempt
                            self.logger.warning(
                                f"⚠️ Intento {attempt + 1} falló para {func.__name__}: {e}. "
                                f"Reintentando en {wait_time}s..."
                            )
                            time.sleep(wait_time)
                        else:
                            self.logger.error(f"❌ Todos los intentos fallaron para {func.__name__}: {e}")
                
                # Si llegamos aquí, todos los intentos fallaron
                raise last_exception
            
            return wrapper
        return decorator
    
    def get_worker_health_summary(self) -> Dict[str, Dict]:
        """
        Obtiene resumen de salud de todos los workers
        
        Returns:
            Diccionario con estado de salud de cada worker
        """
        summary = {}
        
        for worker in self.workers:
            performance = self.worker_performance.get(worker, [])
            last_check = self.last_connectivity_check.get(worker)
            
            summary[worker] = {
                'status': 'healthy' if self.worker_status.get(worker, False) else 'unhealthy',
                'last_check': last_check.isoformat() if last_check else None,
                'avg_response_time': sum(performance) / len(performance) if performance else None,
                'recent_operations': len(performance),
                'adaptive_timeout': self.get_adaptive_timeout(worker)
            }
        
        return summary


class ResilientSSHManager:
    """Gestor de SSH resiliente con validación y recuperación"""
    
    def __init__(self, network_manager: NetworkManager, ssh_user: str, ssh_pass: str):
        """
        Inicializa el gestor SSH resiliente
        
        Args:
            network_manager: Instancia del gestor de red
            ssh_user: Usuario SSH
            ssh_pass: Contraseña SSH
        """
        self.network_manager = network_manager
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.logger = logging.getLogger('ssh_manager')
    
    def execute_command(self, worker: str, command: str, timeout: Optional[int] = None) -> Optional[str]:
        """
        Ejecuta comando SSH con validación previa y manejo de errores
        
        Args:
            worker: Worker destino
            command: Comando a ejecutar
            timeout: Timeout específico (usa adaptativo si es None)
            
        Returns:
            Salida del comando o None si falla
        """
        start_time = time.time()
        
        try:
            # 1. Verificar conectividad básica
            if not self.network_manager.check_connectivity(worker):
                self.logger.warning(f"❌ Worker {worker} no accesible - saltando comando")
                return None
            
            # 2. Determinar timeout
            if timeout is None:
                timeout = self.network_manager.get_adaptive_timeout(worker)
            
            # 3. Preparar comando SSH
            ssh_cmd = self._build_ssh_command(worker, command, timeout)
            
            # 4. Ejecutar con timeout
            self.logger.debug(f"Ejecutando en {worker} (timeout: {timeout}s): {command[:50]}...")
            
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            operation_time = time.time() - start_time
            self.network_manager.record_operation_time(worker, operation_time)
            
            if result.returncode == 0:
                self.network_manager.worker_status[worker] = True
                self.logger.debug(f"✅ SSH exitoso en {worker} ({operation_time:.1f}s)")
                return result.stdout.strip()
            else:
                self.logger.warning(f"⚠️ SSH error en {worker}: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            operation_time = time.time() - start_time
            self.logger.error(f"⏰ Timeout SSH en {worker} después de {operation_time:.1f}s")
            self.network_manager.worker_status[worker] = False
            return None
            
        except Exception as e:
            operation_time = time.time() - start_time
            self.logger.error(f"❌ Error SSH en {worker} ({operation_time:.1f}s): {e}")
            self.network_manager.worker_status[worker] = False
            return None
    
    def _build_ssh_command(self, worker: str, command: str, timeout: int) -> list:
        """
        Construye comando SSH optimizado
        
        Args:
            worker: Worker destino
            command: Comando a ejecutar
            timeout: Timeout total
            
        Returns:
            Lista con comando SSH completo
        """
        # Timeout de conexión: máximo 1/3 del timeout total
        connect_timeout = min(timeout // 3, 10)
        
        return [
            "sshpass", "-p", self.ssh_pass, "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=yes",
            f"{self.ssh_user}@{worker}",
            command
        ]
    
    @property
    def resilient_execute(self):
        """
        Decorator que aplica reintentos automáticos a execute_command
        """
        return self.network_manager.retry_with_backoff(max_attempts=3)(self.execute_command)


# Función de conveniencia para compatibilidad con código existente
def create_resilient_ssh_manager(workers: list, ssh_user: str, ssh_pass: str) -> ResilientSSHManager:
    """
    Crea instancia completa del sistema SSH resiliente
    
    Args:
        workers: Lista de workers
        ssh_user: Usuario SSH
        ssh_pass: Contraseña SSH
        
    Returns:
        Instancia configurada de ResilientSSHManager
    """
    network_manager = NetworkManager(workers)
    return ResilientSSHManager(network_manager, ssh_user, ssh_pass)


if __name__ == "__main__":
    # Test básico del sistema
    import logging
    
    logging.basicConfig(level=logging.DEBUG)
    
    # Crear gestor para workers de prueba
    test_workers = ["hast-wn1", "hast-wn2"]
    ssh_manager = create_resilient_ssh_manager(test_workers, "stack", "stack")
    
    # Test de conectividad
    for worker in test_workers:
        print(f"\n🔍 Testing {worker}:")
        print(f"  Conectividad: {'✅' if ssh_manager.network_manager.check_connectivity(worker) else '❌'}")
        print(f"  Timeout adaptativo: {ssh_manager.network_manager.get_adaptive_timeout(worker)}s")
        
        # Test comando simple
        result = ssh_manager.execute_command(worker, "echo 'test'")
        print(f"  Comando test: {'✅' if result else '❌'}")
    
    # Mostrar resumen de salud
    print(f"\n📊 Resumen de salud:")
    health = ssh_manager.network_manager.get_worker_health_summary()
    for worker, status in health.items():
        print(f"  {worker}: {status['status']} (timeout: {status['adaptive_timeout']}s)")