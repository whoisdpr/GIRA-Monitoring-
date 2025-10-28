#!/usr/bin/env python3
import subprocess
import sqlite3
import smtplib
import time
import xml.etree.ElementTree as ET
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict

# Importar el nuevo sistema de red resiliente
from network_manager import create_resilient_ssh_manager
# Importar el sistema de seguridad
from security_manager import SecurityManager, SSHAuthManager
# Importar el sistema de monitoreo paralelo
from parallel_monitor import ParallelMonitor
# Importar gestión de alertas mejorada
from vm_alert_manager import AlertManager, AlertLevel, get_alert_subject
# Importar agrupación de VMs
from vm_grouper import VMGrouper, ProjectMetrics

def log(msg):
    """Escribe en log con timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}\n"
    print(line.strip())
    # Usar nombre de archivo por defecto si LOG_FILE no está definido aún
    log_file = globals().get('LOG_FILE', 'vm_monitor.log')
    with open(log_file, "a") as f:
        f.write(line)

# ============================================================================
# CONFIGURACIÓN SEGURA - Cargada desde config.env con cifrado
# ============================================================================

# Inicializar gestor de seguridad
security_manager = None
ssh_auth_manager = None

def initialize_security():
    """Inicializa el sistema de seguridad"""
    global security_manager, ssh_auth_manager
    
    if security_manager is None:
        try:
            security_manager = SecurityManager("config.env")
            ssh_auth_manager = SSHAuthManager(security_manager)
            log("🔐 Sistema de seguridad inicializado")
        except Exception as e:
            log(f"❌ Error inicializando seguridad: {e}")
            log("💡 Ejecute: python3 setup_security.py")
            raise
    
    return security_manager, ssh_auth_manager

def get_secure_config():
    """Obtiene configuración segura"""
    sec_mgr, auth_mgr = initialize_security()
    
    return {
        # Workers
        'WORKERS': sec_mgr.get_config_value('WORKERS', 'hast-wn1,hast-wn2,hast-wn3,hast-wn4,hast-wn5,hast-wn6,hast-wn7').split(','),
        
        # SSH (gestionado por SSHAuthManager)
        'SSH_USER': auth_mgr.ssh_user,
        'SSH_PASS': auth_mgr.ssh_pass,  # Ya descifrado
        'SSH_AUTH_MANAGER': auth_mgr,
        
        # Email
        'EMAIL_FROM': sec_mgr.get_config_value('EMAIL_FROM', 'hast.pucp@gmail.com'),
        'EMAIL_PASS': sec_mgr.get_config_value('EMAIL_PASS'),  # Descifrado automáticamente
        'EMAIL_TO': sec_mgr.get_config_value('EMAIL_TO', 'maliagaa@pucp.edu.pe,jbzambrano@pucp.edu.pe').split(','),
        'SMTP_SERVER': sec_mgr.get_config_value('SMTP_SERVER', 'smtp.gmail.com'),
        'SMTP_PORT': int(sec_mgr.get_config_value('SMTP_PORT', '587')),
        
        # Monitoreo
        'CHECK_INTERVAL': int(sec_mgr.get_config_value('CHECK_INTERVAL', '300')),
        'A_MODERATE_MAX': int(sec_mgr.get_config_value('A_MODERATE_MAX', '61')),
        'A_HIGH_MAX': int(sec_mgr.get_config_value('A_HIGH_MAX', '100')),
        'CRITICAL_SAMPLES': int(sec_mgr.get_config_value('CRITICAL_SAMPLES', '13')),
        'CRITICAL_SAMPLE_INTERVAL': int(sec_mgr.get_config_value('CRITICAL_SAMPLE_INTERVAL', '5')),
        'CRITICAL_THRESHOLD_SAMPLES': int(sec_mgr.get_config_value('CRITICAL_THRESHOLD_SAMPLES', '10')),
        'CRITICAL_COOLDOWN': int(sec_mgr.get_config_value('CRITICAL_COOLDOWN', '600')),
        
        # Archivos
        'DB_FILE': sec_mgr.get_config_value('DB_FILE', 'vm_monitor.db'),
        'LOG_FILE': sec_mgr.get_config_value('LOG_FILE', 'vm_monitor.log'),
        'PID_FILE': sec_mgr.get_config_value('PID_FILE', 'vm_monitor.pid'),
        
        # Reportes
        'REPORT_TIMES': sec_mgr.get_config_value('REPORT_TIMES', '07:00,19:00').split(','),
    }

# Cargar configuración segura al inicio
config = get_secure_config()

# Variables globales para compatibilidad con código existente
WORKERS = config['WORKERS']
SSH_USER = config['SSH_USER']
SSH_PASS = config['SSH_PASS']
DB_FILE = config['DB_FILE']
LOG_FILE = config['LOG_FILE']
PID_FILE = config['PID_FILE']

EMAIL_FROM = config['EMAIL_FROM']
EMAIL_PASS = config['EMAIL_PASS']
EMAIL_TO = config['EMAIL_TO']
SMTP_SERVER = config['SMTP_SERVER']
SMTP_PORT = config['SMTP_PORT']

# Nuevos parámetros para el sistema basado en parámetro A
A_MODERATE_MAX = config['A_MODERATE_MAX']
A_HIGH_MAX = config['A_HIGH_MAX']

CHECK_INTERVAL = config['CHECK_INTERVAL']
REPORT_TIMES = config['REPORT_TIMES']

# Sistema de debouncing para alertas críticas
CRITICAL_SAMPLES = config['CRITICAL_SAMPLES']
CRITICAL_SAMPLE_INTERVAL = config['CRITICAL_SAMPLE_INTERVAL']
CRITICAL_THRESHOLD_SAMPLES = config['CRITICAL_THRESHOLD_SAMPLES']
CRITICAL_COOLDOWN = config['CRITICAL_COOLDOWN']

# Almacena timestamp de últimas alertas críticas para cooldown
critical_alerts_sent = defaultdict(lambda: None)
# Almacena procesos de debouncing activos
active_debouncing = defaultdict(lambda: None)

# Inicializar sistema SSH resiliente
resilient_ssh = None
# Inicializar monitor paralelo
parallel_monitor = None

def initialize_resilient_ssh():
    """Inicializa el sistema SSH resiliente con autenticación segura"""
    global resilient_ssh
    if resilient_ssh is None:
        # Crear una versión modificada que usa el gestor de autenticación SSH
        from network_manager import NetworkManager, ResilientSSHManager
        
        # Obtener gestor de autenticación
        _, auth_manager = initialize_security()
        
        # Crear network manager
        network_manager = NetworkManager(WORKERS)
        
        # Crear SSH manager que usa el sistema de autenticación segura
        class SecureResilientSSHManager(ResilientSSHManager):
            def __init__(self, network_manager, auth_manager):
                self.network_manager = network_manager
                self.auth_manager = auth_manager
                self.ssh_user = auth_manager.ssh_user
                self.ssh_pass = auth_manager.ssh_pass
                self.logger = logging.getLogger('secure_ssh_manager')
            
            def execute_command(self, worker, command, timeout=None):
                """Ejecuta comando usando autenticación segura"""
                start_time = time.time()
                
                try:
                    # 1. Verificar conectividad básica
                    if not self.network_manager.check_connectivity(worker):
                        self.logger.warning(f"❌ Worker {worker} no accesible - saltando comando")
                        return None
                    
                    # 2. Determinar timeout
                    if timeout is None:
                        timeout = self.network_manager.get_adaptive_timeout(worker)
                    
                    # 3. Usar comando SSH del auth manager
                    ssh_cmd = self.auth_manager.build_ssh_command(worker, command, timeout)
                    
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
            
            def resilient_execute(self, worker, command, timeout=None):
                """Ejecuta comando con reintentos automáticos"""
                retry_func = self.network_manager.retry_with_backoff(max_attempts=3)(self.execute_command)
                return retry_func(worker, command, timeout)
        
        # Crear instancia con autenticación segura
        resilient_ssh = SecureResilientSSHManager(network_manager, auth_manager)
        
        log("🔐 Sistema SSH resiliente con autenticación segura inicializado")
    return resilient_ssh

def initialize_parallel_monitor():
    """Inicializa el sistema de monitoreo paralelo"""
    global parallel_monitor
    if parallel_monitor is None:
        # Obtener SSH manager
        ssh_manager = initialize_resilient_ssh()
        
        # Crear monitor paralelo
        parallel_monitor = ParallelMonitor(
            workers=WORKERS,
            ssh_manager=ssh_manager,
            max_workers=min(len(WORKERS), 7)  # Max 7 workers en paralelo
        )
        
        log("⚡ Sistema de monitoreo paralelo inicializado")
    return parallel_monitor

# Inicializar gestor de alertas mejorado
alert_manager = AlertManager()
project_metrics = ProjectMetrics()

def init_db():
    """Crea tabla si no existe"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS cpu_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            worker TEXT,
            instance_id TEXT,
            cpu_percent REAL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS vm_counts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            worker TEXT,
            count INTEGER
        )
    """)
    conn.commit()
    conn.close()

def ssh_command(worker, cmd):
    """Ejecuta comando SSH usando el sistema resiliente y seguro"""
    ssh_manager = initialize_resilient_ssh()
    
    # Usar el sistema resiliente con reintentos automáticos
    result = ssh_manager.resilient_execute(worker, cmd)
    
    if result is None:
        log(f"❌ Falló comando SSH en {worker} después de reintentos")
    
    return result

def ssh_command_with_timeout(worker, cmd, timeout=None):
    """Ejecuta comando SSH con timeout específico usando autenticación segura"""
    ssh_manager = initialize_resilient_ssh()
    
    # Sin reintentos automáticos para timeouts específicos
    result = ssh_manager.execute_command(worker, cmd, timeout)
    
    if result is None:
        log(f"❌ Falló comando SSH en {worker} (timeout: {timeout}s)")
    
    return result

def get_vm_metadata(worker, vm_name):
    """Obtiene metadatos detallados de una VM usando virsh dumpxml"""
    try:
        xml_output = ssh_command(worker, f"sudo virsh dumpxml {vm_name}")
        if not xml_output:
            return None
            
        # Parsear XML
        root = ET.fromstring(xml_output)
        
        # Extraer información requerida
        metadata = {
            'vm_name': vm_name,
            'worker': worker,
            'project': 'Unknown',
            'display_name': 'Unknown',
            'flavor_name': 'Unknown',
            'vcpus': 1,
            'memory_mb': 0
        }
        
        # Extraer nombre de proyecto
        project_elem = root.find('.//nova:project', {'nova': 'http://openstack.org/xmlns/libvirt/nova/1.0'})
        if project_elem is not None and 'uuid' in project_elem.attrib:
            # Buscar el texto del proyecto (nombre del proyecto)
            project_name = project_elem.text
            if project_name:
                metadata['project'] = project_name.strip()
        
        # Extraer nombre display de la VM
        name_elem = root.find('.//nova:name', {'nova': 'http://openstack.org/xmlns/libvirt/nova/1.0'})
        if name_elem is not None:
            metadata['display_name'] = name_elem.text.strip()
        
        # Extraer nombre del flavor
        flavor_elem = root.find('.//nova:flavor', {'nova': 'http://openstack.org/xmlns/libvirt/nova/1.0'})
        if flavor_elem is not None and 'name' in flavor_elem.attrib:
            metadata['flavor_name'] = flavor_elem.attrib['name']
        
        # Extraer número de vCPUs
        vcpu_elem = root.find('vcpu')
        if vcpu_elem is not None:
            try:
                metadata['vcpus'] = int(vcpu_elem.text)
            except (ValueError, TypeError):
                metadata['vcpus'] = 1
        
        # Extraer memoria (opcional para reportes)
        memory_elem = root.find('memory')
        if memory_elem is not None:
            try:
                # Memoria está en KiB, convertir a MB
                memory_kib = int(memory_elem.text)
                metadata['memory_mb'] = memory_kib // 1024
            except (ValueError, TypeError):
                metadata['memory_mb'] = 0
        
        return metadata
        
    except Exception as e:
        log(f"Error obteniendo metadatos de {vm_name} en {worker}: {e}")
        return None

def calculate_parameter_a(cpu_percent, vcpus):
    """Calcula el parámetro A = CPU% / vCPUs"""
    if vcpus == 0:
        return 0
    return cpu_percent / vcpus

def classify_vm_status(parameter_a):
    """Clasifica el estado de la VM basado en el parámetro A"""
    if parameter_a < A_MODERATE_MAX:
        return "Moderado", "🟡"
    elif parameter_a < A_HIGH_MAX:
        return "Alto", "🟠"
    else:
        return "Crítico", "🔴"

def handle_alto_alert(worker, vm_name, metadata, cpu_percent, parameter_a):
    """
    Maneja alertas de nivel ALTO con consolidación y quiet hours.
    
    Reglas:
    - Durante quiet hours (22:00-07:00): solo consolidar, no enviar inmediato
    - Horario laboral: enviar inmediato consolidado
    - Máximo 1 alerta por proyecto por hora
    """
    # Obtener información de la alerta
    alert = {
        'vm_name': vm_name,
        'display_name': metadata['display_name'],
        'project': metadata['project'],
        'worker': worker,
        'cpu_percent': cpu_percent,
        'parameter_a': parameter_a,
        'level': AlertLevel.ALTO,
        'metadata': metadata
    }
    
    # Añadir a alertas pendientes para consolidación
    alert_manager.add_pending_alert(alert)
    
    project = metadata['project']
    is_quiet_hours = alert_manager.is_quiet_hours()
    
    # Verificar si debe consolidarse y enviar
    should_consolidate = alert_manager.should_consolidate_alert(project, AlertLevel.ALTO)
    
    if not should_consolidate and is_quiet_hours:
        # Durante quiet hours, solo guardar sin enviar
        log(f"🟡 Alerta ALTO de {project} guardada para consolidación (quiet hours)")
        return
    
    # Obtener todas las alertas pendientes del proyecto
    pending_alerts = alert_manager.get_pending_alerts_for_project(project)
    
    if len(pending_alerts) == 0:
        return
    
    # Formatear y enviar consolidadas
    if len(pending_alerts) == 1:
        # Alerta sola
        subject = get_alert_subject(AlertLevel.ALTO, pending_alerts[0]['display_name'], project)
        body = alert_manager.format_alert_body(pending_alerts)
    else:
        # Alertas consolidadas
        subject = f"🟡 [ALERTA CONSOLIDADA] {project} - {len(pending_alerts)} VMs en estado ALTO"
        body = alert_manager.format_alert_body(pending_alerts, project)
    
    # Solo enviar si NO es quiet hours O si es first time del proyecto
    if not is_quiet_hours or not alert_manager.should_consolidate_alert(project, AlertLevel.ALTO):
        send_email(subject, body)
        log(f"✉️ Alerta ALTO consolidada enviada para {project} ({len(pending_alerts)} VMs)")
    
    # Limpiar alertas pendientes
    alert_manager.clear_pending_alerts(project)

def perform_critical_debouncing(worker, vm_name, initial_cpu, initial_vcpus):
    """Realiza el proceso de debouncing para una VM crítica"""
    log(f"Iniciando debouncing para {vm_name} en {worker} (CPU inicial: {initial_cpu:.1f}%)")
    
    critical_samples = 0
    total_samples = 0
    
    for i in range(CRITICAL_SAMPLES):
        time.sleep(CRITICAL_SAMPLE_INTERVAL)
        
        # Obtener nueva muestra de CPU
        vms_cpu = get_all_vms_cpu(worker)
        if vm_name not in vms_cpu:
            log(f"VM {vm_name} ya no existe durante debouncing")
            return False
            
        current_cpu = vms_cpu[vm_name]
        parameter_a = calculate_parameter_a(current_cpu, initial_vcpus)
        status, _ = classify_vm_status(parameter_a)
        
        total_samples += 1
        if status == "Crítico":
            critical_samples += 1
            
        log(f"Debouncing {vm_name}: muestra {total_samples}/{CRITICAL_SAMPLES}, "
            f"CPU: {current_cpu:.1f}%, A: {parameter_a:.1f}, estado: {status}")
    
    # Decidir si enviar alerta
    should_alert = critical_samples >= CRITICAL_THRESHOLD_SAMPLES
    log(f"Debouncing {vm_name} completado: {critical_samples}/{total_samples} muestras críticas. "
        f"Alerta: {'SÍ' if should_alert else 'NO'}")
    
    return should_alert

def send_critical_alert(worker, vm_name, metadata, cpu_percent, parameter_a):
    """
    Envía alerta crítica confirmada con soporte para escalation.
    
    Integra:
    - Nombres amigables (display_name + proyecto)
    - Verificación de quiet hours
    - Escalation rules (supervisor/director después de 10-30 min)
    """
    now = datetime.now()
    key = f"{worker}:{vm_name}"
    
    # Obtener tiempo desde que empezó el problema
    alert_start = critical_alerts_sent.get(key)
    time_since_alert = 0
    if alert_start:
        time_since_alert = (now - alert_start).total_seconds()
    
    # Determinar nivel de escalation
    escalation_level = alert_manager.get_escalation_level(
        key, AlertLevel.CRITICO, time_since_alert
    )
    
    # Obtener nombre amigable
    display_id = VMGrouper.get_vm_identifier(vm_name, metadata)
    
    # Construir asunto y cuerpo
    subject = get_alert_subject(
        AlertLevel.CRITICO,
        metadata['display_name'],
        metadata['project'],
        is_consolidated=False
    )
    
    # Formatear cuerpo usando el nuevo sistema
    alert_data = {
        'vm_name': vm_name,
        'display_name': metadata['display_name'],
        'project': metadata['project'],
        'worker': worker,
        'cpu_percent': cpu_percent,
        'parameter_a': parameter_a,
        'level': AlertLevel.CRITICO,
        'metadata': metadata
    }
    
    body = alert_manager.format_alert_body([alert_data])
    
    # Agregar info de escalation si aplica
    if escalation_level != "normal":
        body += f"\n\n⚠️ ESCALATION: {escalation_level.upper()}"
        body += f"\n   Tiempo persistente: {time_since_alert/60:.1f} minutos"
    
    body += f"""

VERIFICACIÓN:
✅ Confirmado por proceso de debouncing
✅ {CRITICAL_THRESHOLD_SAMPLES}/{CRITICAL_SAMPLES} muestras fueron críticas
✅ No es falso positivo

📊 HISTÓRICO:
• Última alerta: {alert_start.strftime('%Y-%m-%d %H:%M:%S') if alert_start else 'Primera vez'}
• Persistencia: {time_since_alert/60:.1f} minutos

Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    # Enviar email con escalation si aplica
    send_email(subject, body, escalation_level=escalation_level)
    save_alert(worker, vm_name, cpu_percent)
    
    # Marcar cooldown
    critical_alerts_sent[key] = now
    
    log(f"🚨 ALERTA CRÍTICA enviada: {display_id} (CPU: {cpu_percent:.1f}%, A: {parameter_a:.1f}) "
        f"[Escalation: {escalation_level}]")

def check_critical_vm(worker, vm_name, cpu_percent, metadata):
    """Verifica si una VM crítica debe generar alerta (con debouncing)"""
    key = f"{worker}:{vm_name}"
    now = datetime.now()
    
    # Verificar cooldown
    last_alert = critical_alerts_sent[key]
    if last_alert and (now - last_alert).total_seconds() < CRITICAL_COOLDOWN:
        time_remaining = CRITICAL_COOLDOWN - (now - last_alert).total_seconds()
        log(f"⏳ VM crítica {vm_name} en cooldown - {time_remaining/60:.1f} min restantes")
        return
    
    # Verificar si ya hay debouncing activo
    if active_debouncing[key]:
        log(f"🔄 Debouncing ya activo para {vm_name} en {worker}")
        return
    
    # Marcar debouncing como activo
    active_debouncing[key] = now
    
    try:
        # Realizar debouncing
        should_alert = perform_critical_debouncing(worker, vm_name, cpu_percent, metadata['vcpus'])
        
        if should_alert:
            # Obtener CPU actual después del debouncing
            vms_cpu = get_all_vms_cpu(worker)
            if vm_name in vms_cpu:
                current_cpu = vms_cpu[vm_name]
                current_a = calculate_parameter_a(current_cpu, metadata['vcpus'])
                send_critical_alert(worker, vm_name, metadata, current_cpu, current_a)
        else:
            log(f"Falso positivo detectado para {vm_name} en {worker} - no se envía alerta")
            
    finally:
        # Limpiar debouncing activo
        active_debouncing[key] = None

def get_vms(worker):
    """Obtiene lista de VMs activas en un worker"""
    cmd = "sudo virsh list --name 2>/dev/null"
    output = ssh_command(worker, cmd)
    if output:
        # Filtrar líneas vacías, setlocale y otros errores
        vms = [line.strip() for line in output.split("\n") 
               if line.strip() and 'setlocale' not in line.lower() 
               and 'error' not in line.lower() and not line.startswith('-')]
        return vms
    return []

def get_all_vms_cpu(worker):
    """Obtiene CPU de todas las VMs en un worker con un solo comando SSH resiliente"""
    # Script optimizado que ejecuta en el worker remoto
    script = """
sudo virsh list --name 2>/dev/null | grep -v setlocale | grep -v error | while read vm; do
    [ -z "$vm" ] && continue
    pid=$(ps aux | grep "qemu.*$vm" | grep -v grep | awk '{print $2}' | head -1)
    [ -z "$pid" ] && continue
    
    # Primera lectura
    read utime1 stime1 < <(awk '{print $14, $15}' /proc/$pid/stat 2>/dev/null)
    [ -z "$utime1" ] && continue
    
    # Espera 1 segundo
    sleep 1
    
    # Segunda lectura
    read utime2 stime2 < <(awk '{print $14, $15}' /proc/$pid/stat 2>/dev/null)
    [ -z "$utime2" ] && continue
    
    # Calcula CPU (diferencia de jiffies en 1 segundo, 100 jiffies = 1 seg)
    cpu=$(echo "scale=2; (($utime2 - $utime1) + ($stime2 - $stime1))" | bc)
    
    echo "$vm:$cpu"
done
"""
    
    # Usar timeout extendido para este comando complejo
    output = ssh_command_with_timeout(worker, script, timeout=90)
    result = {}
    
    if output:
        for line in output.split("\n"):
            if ":" in line:
                vm, cpu = line.strip().split(":")
                try:
                    result[vm] = float(cpu)
                except:
                    pass
    
    if result:
        log(f"✅ Obtenidas métricas CPU de {len(result)} VMs en {worker}")
    else:
        log(f"⚠️ Sin métricas CPU de {worker}")
    
    return result

def save_alert(worker, instance_id, cpu_percent):
    """Guarda alerta en la BD"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO cpu_alerts (timestamp, worker, instance_id, cpu_percent) VALUES (?, ?, ?, ?)",
              (timestamp, worker, instance_id, cpu_percent))
    conn.commit()
    conn.close()

def save_vm_count(worker, count):
    """Guarda conteo de VMs en la BD"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO vm_counts (timestamp, worker, count) VALUES (?, ?, ?)",
              (timestamp, worker, count))
    conn.commit()
    conn.close()

def send_email(subject, body, recipients=None, escalation_level="normal"):
    """
    Envía correo vía Gmail SMTP.
    
    Args:
        subject: Asunto del correo
        body: Cuerpo del correo
        recipients: Lista de destinatarios (default: EMAIL_TO)
        escalation_level: "normal", "supervisor", "director"
    """
    try:
        # Determinar destinatarios
        to_recipients = recipients if recipients else EMAIL_TO
        
        # Agregar destinatarios según escalation (si están en config)
        if escalation_level == "supervisor":
            # Intenta añadir supervisor si está en config
            supervisor_email = config.get('ESCALATION_SUPERVISOR', None)
            if supervisor_email and supervisor_email not in to_recipients:
                to_recipients = list(to_recipients) + [supervisor_email]
        
        elif escalation_level == "director":
            # Intenta añadir director si está en config
            director_email = config.get('ESCALATION_DIRECTOR', None)
            if director_email and director_email not in to_recipients:
                to_recipients = list(to_recipients) + [director_email]
        
        # Asegurar que es lista
        if isinstance(to_recipients, str):
            to_recipients = [to_recipients]
        
        msg = MIMEMultipart()
        msg["From"] = EMAIL_FROM
        msg["To"] = ", ".join(to_recipients)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_FROM, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        
        escalation_str = f" [Escalation: {escalation_level}]" if escalation_level != "normal" else ""
        log(f"✉️ Correo enviado: {subject}{escalation_str}")
    except Exception as e:
        log(f"❌ Error enviando correo: {e}")

def get_network_health_report():
    """Genera reporte de salud de la red y conectividad"""
    ssh_manager = initialize_resilient_ssh()
    health_summary = ssh_manager.network_manager.get_worker_health_summary()
    
    healthy_workers = [w for w, status in health_summary.items() if status['status'] == 'healthy']
    unhealthy_workers = [w for w, status in health_summary.items() if status['status'] == 'unhealthy']
    
    report = f"""
📊 ESTADO DE CONECTIVIDAD DE WORKERS:

✅ Workers Saludables ({len(healthy_workers)}):
"""
    
    for worker in healthy_workers:
        status = health_summary[worker]
        avg_time = status.get('avg_response_time')
        time_str = f"{avg_time:.1f}s" if avg_time else "N/A"
        report += f"  • {worker}: Tiempo promedio: {time_str}, Timeout adaptativo: {status['adaptive_timeout']}s\n"
    
    if unhealthy_workers:
        report += f"""
❌ Workers con Problemas ({len(unhealthy_workers)}):
"""
        for worker in unhealthy_workers:
            status = health_summary[worker]
            last_check = status.get('last_check', 'Nunca')
            report += f"  • {worker}: Última verificación: {last_check}\n"
    
    return report.strip()

def log_network_health():
    """Registra estado de salud de la red en el log"""
    try:
        health_report = get_network_health_report()
        log("=== REPORTE DE SALUD DE RED ===")
        for line in health_report.split('\n'):
            if line.strip():
                log(line.strip())
        log("=== FIN REPORTE DE SALUD ===")
    except Exception as e:
        log(f"Error generando reporte de salud de red: {e}")

def check_and_alert():
    """Monitorea todas las VMs usando el nuevo sistema basado en parámetro A con red resiliente"""
    now = datetime.now()
    
    # Inicializar sistema resiliente
    ssh_manager = initialize_resilient_ssh()
    
    # Log de salud de red cada 30 minutos
    if now.minute in [0, 30]:
        log_network_health()
    
    # Limpia alertas críticas antiguas (más de 2 horas)
    two_hours_ago = now - timedelta(hours=2)
    keys_to_remove = [k for k, v in critical_alerts_sent.items() 
                     if v and v < two_hours_ago]
    for k in keys_to_remove:
        del critical_alerts_sent[k]
    
    # Limpia procesos de debouncing antiguos (más de 5 minutos)
    five_minutes_ago = now - timedelta(minutes=5)
    keys_to_remove = [k for k, v in active_debouncing.items() 
                     if v and v < five_minutes_ago]
    for k in keys_to_remove:
        active_debouncing[k] = None
    
    total_vms_monitored = 0
    workers_with_errors = 0
    
    for worker in WORKERS:
        try:
            # Verificar conectividad antes de proceder
            if not ssh_manager.network_manager.check_connectivity(worker):
                log(f"⚠️ Worker {worker} no accesible - saltando monitoreo")
                workers_with_errors += 1
                continue
            
            # Obtiene CPU de todas las VMs en un solo comando SSH
            vms_cpu = get_all_vms_cpu(worker)
            
            if not vms_cpu:
                log(f"⚠️ Sin datos de {worker}")
                workers_with_errors += 1
                continue
            
            log(f"🔍 Monitoreando {len(vms_cpu)} VMs en {worker}")
            total_vms_monitored += len(vms_cpu)
            
            for vm_name, cpu_percent in vms_cpu.items():
                # Obtener metadatos de la VM
                metadata = get_vm_metadata(worker, vm_name)
                if not metadata:
                    log(f"⚠️ No se pudieron obtener metadatos de {vm_name} en {worker}")
                    continue
                
                # Calcular parámetro A y clasificar estado
                parameter_a = calculate_parameter_a(cpu_percent, metadata['vcpus'])
                status, emoji = classify_vm_status(parameter_a)
                
                # Log detallado para VMs en estado Alto o Crítico
                if status in ["Alto", "Crítico"]:
                    log(f"{emoji} {vm_name} en {worker}: CPU={cpu_percent:.1f}%, "
                        f"vCPUs={metadata['vcpus']}, A={parameter_a:.1f} ({status})")
                
                # Verificar si necesita alerta crítica (solo para VMs críticas)
                if status == "Crítico":
                    # Usar threading para no bloquear el monitoreo principal
                    import threading
                    thread = threading.Thread(
                        target=check_critical_vm,
                        args=(worker, vm_name, cpu_percent, metadata)
                    )
                    thread.daemon = True
                    thread.start()
                    
        except Exception as e:
            log(f"❌ Error monitoreando worker {worker}: {e}")
            workers_with_errors += 1
    
    # Log resumen del ciclo
    log(f"📊 Ciclo completado: {total_vms_monitored} VMs monitoreadas, "
        f"{workers_with_errors} workers con errores")
    
    # Alerta si hay muchos workers con problemas
    if workers_with_errors > len(WORKERS) // 2:
        log(f"⚠️ ALERTA: {workers_with_errors}/{len(WORKERS)} workers con problemas")
        
        # Enviar alerta sobre problemas de conectividad
        subject = "[ALERTA CONECTIVIDAD] Problemas en Workers"
        body = f"""⚠️ PROBLEMAS DE CONECTIVIDAD DETECTADOS

Workers con problemas: {workers_with_errors} de {len(WORKERS)}
VMs monitoreadas exitosamente: {total_vms_monitored}

{get_network_health_report()}

Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}
"""
        send_email(subject, body)

def check_and_alert_parallel():
    """Monitorea todas las VMs usando el sistema paralelo optimizado"""
    now = datetime.now()
    
    # Inicializar monitor paralelo
    monitor = initialize_parallel_monitor()
    
    # Log de salud de red cada 30 minutos
    if now.minute in [0, 30]:
        log_network_health()
    
    # Limpia alertas críticas antiguas (más de 2 horas)
    two_hours_ago = now - timedelta(hours=2)
    keys_to_remove = [k for k, v in critical_alerts_sent.items() 
                     if v and v < two_hours_ago]
    for k in keys_to_remove:
        del critical_alerts_sent[k]
    
    # Limpia procesos de debouncing antiguos (más de 5 minutos)
    five_minutes_ago = now - timedelta(minutes=5)
    keys_to_remove = [k for k, v in active_debouncing.items() 
                     if v and v < five_minutes_ago]
    for k in keys_to_remove:
        active_debouncing[k] = None
    
    try:
        # Ejecutar ciclo de monitoreo paralelo
        log("🔄 Iniciando ciclo de monitoreo paralelo...")
        cycle_result = monitor.execute_monitoring_cycle()
        
        # Procesar resultados
        total_vms_critical = 0
        total_vms_monitored = cycle_result.total_vms
        workers_with_errors = len([w for w in cycle_result.worker_results.values() if w.status == 'failed'])
        
        # Procesar cada worker
        for worker_name, worker_metrics in cycle_result.worker_results.items():
            if worker_metrics.status == 'failed':
                log(f"❌ Worker {worker_name} falló completamente")
                continue
            
            # Procesar VMs del worker
            for vm_name, vm_data in worker_metrics.vms_data.items():
                try:
                    # Calcular parámetro A y clasificar estado
                    cpu_percent = vm_data['cpu_percent']
                    vcpus = vm_data['vcpus']
                    parameter_a = calculate_parameter_a(cpu_percent, vcpus)
                    status, emoji = classify_vm_status(parameter_a)
                    
                    # Crear metadata compatible
                    metadata = {
                        'vcpus': vcpus,
                        'display_name': vm_data['display_name'],
                        'project': vm_data['project'],
                        'flavor_name': vm_data['flavor'],
                        'memory_mb': vm_data['memory_kb'] // 1024 if vm_data['memory_kb'] else 0
                    }
                    
                    # Log detallado para VMs en estado Alto o Crítico
                    if status in ["Alto", "Crítico"]:
                        identifier = VMGrouper.get_vm_identifier(vm_name, metadata)
                        log(f"{emoji} {identifier}: CPU={cpu_percent:.1f}%, A={parameter_a:.1f}")
                    
                    # Manejar según el status
                    if status == "Crítico":
                        total_vms_critical += 1
                        
                        # Usar threading controlado para debouncing
                        import threading
                        thread = threading.Thread(
                            target=check_critical_vm_parallel,
                            args=(worker_name, vm_name, cpu_percent, metadata, monitor.resource_manager)
                        )
                        thread.daemon = True
                        thread.start()
                    
                    elif status == "Alto":
                        # Manejar alertas ALTO con consolidación y quiet hours
                        handle_alto_alert(worker_name, vm_name, metadata, cpu_percent, parameter_a)
                    
                    # Registrar métrica del proyecto
                    project_metrics.add_vm_metric(
                        metadata['project'], vm_name, cpu_percent, parameter_a, status
                    )
                
                except Exception as e:
                    log(f"⚠️ Error procesando {vm_name} en {worker_name}: {e}")
        
        # Log resumen del ciclo paralelo
        log(f"⚡ Ciclo paralelo completado: {total_vms_monitored} VMs en {cycle_result.duration:.1f}s, "
            f"{cycle_result.success_rate:.1%} éxito, {total_vms_critical} críticas")
        
        # Mostrar estadísticas de performance cada 10 ciclos
        if cycle_result.cycle_id % 10 == 0:
            stats = monitor.get_performance_stats()
            avg_duration = stats['recent_performance']['avg_duration']
            avg_vms = stats['recent_performance']['avg_vms_per_cycle']
            log(f"📊 Estadísticas (últimos 10 ciclos): {avg_duration:.1f}s promedio, {avg_vms:.0f} VMs/ciclo")
        
        # Alerta si hay muchos workers con problemas
        if workers_with_errors > len(WORKERS) // 2:
            log(f"⚠️ ALERTA: {workers_with_errors}/{len(WORKERS)} workers con problemas")
            
            # Enviar alerta sobre problemas de conectividad
            subject = "[ALERTA CONECTIVIDAD] Problemas en Workers"
            body = f"""⚠️ PROBLEMAS DE CONECTIVIDAD DETECTADOS

Workers con problemas: {workers_with_errors} de {len(WORKERS)}
VMs monitoreadas exitosamente: {total_vms_monitored}
Duración del ciclo: {cycle_result.duration:.1f}s
Tasa de éxito: {cycle_result.success_rate:.1%}

DETALLES POR WORKER:
"""
            
            for worker_name, worker_metrics in cycle_result.worker_results.items():
                status_icon = "✅" if worker_metrics.status == 'success' else "❌"
                body += f"{status_icon} {worker_name}: {worker_metrics.status} "
                body += f"({len(worker_metrics.vms_data)} VMs, {worker_metrics.collection_time:.1f}s)\n"
            
            body += f"\n{get_network_health_report()}\n"
            body += f"\nTimestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}"
            
            send_email(subject, body)
    
    except Exception as e:
        log(f"❌ Error en ciclo de monitoreo paralelo: {e}")
        # Fallback al sistema original
        log("🔄 Cayendo back al sistema de monitoreo secuencial...")
        check_and_alert_sequential()

def check_critical_vm_parallel(worker, vm_name, cpu_percent, metadata, resource_manager):
    """Verifica VM crítica con control de concurrencia del sistema paralelo"""
    
    # Usar el gestor de recursos del monitor paralelo
    if not resource_manager.acquire_debouncing_slot(timeout=10):
        log(f"⏸️ Debouncing diferido para {vm_name} en {worker} - sistema ocupado")
        return
    
    try:
        # Ejecutar proceso de debouncing existente
        check_critical_vm(worker, vm_name, cpu_percent, metadata)
    finally:
        resource_manager.release_debouncing_slot()

# Mantener función original como fallback
def check_and_alert_sequential():
    """Monitorea todas las VMs usando el sistema secuencial (fallback)"""
    return check_and_alert()

def send_vm_report():
    """Envía reporte programado completo con metadatos de todas las VMs (7am/7pm)"""
    now = datetime.now()
    total_vms = 0
    vms_by_status = {"Moderado": [], "Alto": [], "Crítico": []}
    worker_counts = {}
    
    log("Generando reporte programado completo...")
    
    for worker in WORKERS:
        vms_cpu = get_all_vms_cpu(worker)
        if not vms_cpu:
            worker_counts[worker] = 0
            continue
            
        worker_counts[worker] = len(vms_cpu)
        total_vms += len(vms_cpu)
        
        for vm_name, cpu_percent in vms_cpu.items():
            # Obtener metadatos detallados
            metadata = get_vm_metadata(worker, vm_name)
            if not metadata:
                continue
                
            # Calcular parámetro A y clasificar
            parameter_a = calculate_parameter_a(cpu_percent, metadata['vcpus'])
            status, emoji = classify_vm_status(parameter_a)
            
            vm_info = {
                'vm_name': vm_name,
                'display_name': metadata['display_name'],
                'project': metadata['project'],
                'flavor': metadata['flavor_name'],
                'worker': worker,
                'vcpus': metadata['vcpus'],
                'memory_mb': metadata['memory_mb'],
                'cpu_percent': cpu_percent,
                'parameter_a': parameter_a,
                'status': status
            }
            
            vms_by_status[status].append(vm_info)
    
    # Construir reporte completo
    body = f"[REPORTE PROGRAMADO] Estado Completo de VMs - {now.strftime('%Y-%m-%d %H:%M')}\n\n"
    
    # Resumen por worker
    body += "📊 RESUMEN POR WORKER:\n"
    for worker, count in worker_counts.items():
        body += f"  {worker}: {count} VMs\n"
    body += f"  TOTAL: {total_vms} VMs\n\n"
    
    # Resumen por estado
    body += "📈 RESUMEN POR ESTADO:\n"
    for status in ["Moderado", "Alto", "Crítico"]:
        count = len(vms_by_status[status])
        emoji = "🟡" if status == "Moderado" else "🟠" if status == "Alto" else "🔴"
        body += f"  {emoji} {status}: {count} VMs\n"
    body += "\n"
    
    # Detalle por estado
    for status in ["Crítico", "Alto", "Moderado"]:  # Orden de prioridad
        vms = vms_by_status[status]
        if not vms:
            continue
            
        emoji = "🔴" if status == "Crítico" else "🟠" if status == "Alto" else "🟡"
        body += f"{emoji} VMs EN ESTADO {status.upper()} ({len(vms)}):\n"
        
        for vm in sorted(vms, key=lambda x: x['parameter_a'], reverse=True):
            body += f"  • {vm['display_name']} ({vm['vm_name']})\n"
            body += f"    Proyecto: {vm['project']}\n"
            body += f"    Flavor: {vm['flavor']}\n"
            body += f"    Worker: {vm['worker']}\n"
            body += f"    vCPUs: {vm['vcpus']} | RAM: {vm['memory_mb']}MB\n"
            body += f"    CPU: {vm['cpu_percent']:.1f}% | Parámetro A: {vm['parameter_a']:.1f}\n\n"
    
    body += f"Generado: {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    # Guardar conteos en BD
    for worker, count in worker_counts.items():
        save_vm_count(worker, count)
    
    send_email("[REPORTE PROGRAMADO] Estado Completo de VMs", body)
    log(f"Reporte programado enviado - {total_vms} VMs analizadas")

def send_hourly_alert_report():
    """Envía reporte horario mostrando solo VMs en estado Moderado y Alto"""
    now = datetime.now()
    total_vms = 0
    moderate_vms = []
    high_vms = []
    critical_count = 0
    
    log("Generando reporte horario de seguimiento...")
    
    for worker in WORKERS:
        vms_cpu = get_all_vms_cpu(worker)
        if not vms_cpu:
            continue
            
        total_vms += len(vms_cpu)
        
        for vm_name, cpu_percent in vms_cpu.items():
            # Obtener metadatos detallados
            metadata = get_vm_metadata(worker, vm_name)
            if not metadata:
                continue
                
            # Calcular parámetro A y clasificar
            parameter_a = calculate_parameter_a(cpu_percent, metadata['vcpus'])
            status, emoji = classify_vm_status(parameter_a)
            
            vm_info = {
                'vm_name': vm_name,
                'display_name': metadata['display_name'],
                'project': metadata['project'],
                'flavor': metadata['flavor_name'],
                'worker': worker,
                'vcpus': metadata['vcpus'],
                'cpu_percent': cpu_percent,
                'parameter_a': parameter_a
            }
            
            if status == "Moderado":
                moderate_vms.append(vm_info)
            elif status == "Alto":
                high_vms.append(vm_info)
            elif status == "Crítico":
                critical_count += 1
    
    # Construir reporte horario
    body = f"[REPORTE HORARIO] Seguimiento de VMs - {now.strftime('%H:%M')}\n\n"
    
    body += f"📊 TOTAL VMs MONITOREADAS: {total_vms}\n"
    body += f"🔴 VMs Críticas: {critical_count} (alertas separadas si confirmadas)\n\n"
    
    if not moderate_vms and not high_vms:
        body += "✅ ESTADO ÓPTIMO\n"
        body += "• Todas las VMs funcionando dentro de parámetros normales\n"
        body += "• No hay VMs en estado Moderado o Alto que requieran atención\n"
    else:
        # VMs en estado Alto (prioridad)
        if high_vms:
            body += f"� VMs EN ESTADO ALTO ({len(high_vms)}) - REQUIEREN ATENCIÓN:\n"
            for vm in sorted(high_vms, key=lambda x: x['parameter_a'], reverse=True):
                body += f"  • {vm['display_name']} ({vm['vm_name']})\n"
                body += f"    Proyecto: {vm['project']} | Worker: {vm['worker']}\n"
                body += f"    Flavor: {vm['flavor']} | vCPUs: {vm['vcpus']}\n"
                body += f"    CPU: {vm['cpu_percent']:.1f}% | Parámetro A: {vm['parameter_a']:.1f}\n\n"
        
        # VMs en estado Moderado (informativo)
        if moderate_vms:
            body += f"� VMs EN ESTADO MODERADO ({len(moderate_vms)}) - MONITOREO:\n"
            for vm in sorted(moderate_vms, key=lambda x: x['parameter_a'], reverse=True):
                body += f"  • {vm['display_name']} ({vm['vm_name']})\n"
                body += f"    Proyecto: {vm['project']} | Worker: {vm['worker']}\n"
                body += f"    Flavor: {vm['flavor']} | vCPUs: {vm['vcpus']}\n"
                body += f"    CPU: {vm['cpu_percent']:.1f}% | Parámetro A: {vm['parameter_a']:.1f}\n\n"
    
    body += f"Generado: {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    send_email("[REPORTE HORARIO] Seguimiento de VMs", body)
    log(f"Reporte horario enviado - {len(moderate_vms)} Moderadas, {len(high_vms)} Altas, {critical_count} Críticas")

def should_send_report():
    """Verifica si es hora de enviar reporte de conteo (7am/7pm) con ventana de 5 minutos"""
    current_time = datetime.now()
    current_hour = current_time.hour
    current_minute = current_time.minute
    
    # Ventana de 5 minutos para las 07:00 y 19:00
    if (current_hour == 7 or current_hour == 19) and current_minute <= 5:
        return True
    return False

def should_send_hourly_alert_report():
    """Verifica si es hora de enviar reporte horario de alertas (primeros 5 minutos de cada hora)"""
    current_time = datetime.now()
    return current_time.minute <= 5  # Ventana de 5 minutos para no perder reportes

def initialize_parallel_monitor():
    """Inicializa el sistema de monitoreo paralelo"""
    try:
        from parallel_monitor import ParallelMonitor
        
        # Obtener ssh_manager del sistema resiliente
        ssh_manager = initialize_resilient_ssh()
        
        # Configuración optimizada
        max_workers = min(len(WORKERS), 8)  # Máximo 8 workers concurrentes
        
        monitor = ParallelMonitor(WORKERS, ssh_manager, max_workers)
        log(f"✅ Monitor paralelo inicializado: {max_workers} workers máximo")
        return monitor
        
    except ImportError as e:
        log(f"⚠️ No se pudo importar monitor paralelo: {e}")
        return None
    except Exception as e:
        log(f"❌ Error inicializando monitor paralelo: {e}")
        return None

def log_network_health():
    """Log periódico del estado de la red"""
    health_report = get_network_health_report()
    log("📊 Estado de conectividad:")
    for line in health_report.split('\n'):
        if line.strip():
            log(f"   {line.strip()}")

def main():
    """Loop principal de monitoreo con sistema paralelo resiliente"""
    log("🚀 Iniciando vm-monitoring con sistema paralelo resiliente")
    
    # Configurar logging más detallado
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Guarda PID del proceso actual
    import os
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    
    init_db()
    
    # Inicializar sistema SSH resiliente
    ssh_manager = initialize_resilient_ssh()
    log("✅ Sistema de conectividad resiliente inicializado")
    
    # Inicializar monitor paralelo
    parallel_monitor = initialize_parallel_monitor()
    use_parallel = parallel_monitor is not None
    
    if use_parallel:
        log("⚡ Usando sistema de monitoreo PARALELO optimizado")
    else:
        log("🔄 Usando sistema de monitoreo SECUENCIAL (fallback)")
    
    # Test inicial de conectividad
    log("🔍 Verificando conectividad inicial...")
    health_report = get_network_health_report()
    for line in health_report.split('\n'):
        if line.strip():
            log(line.strip())
    
    last_report_day = None
    last_report_hour = None
    last_hourly_alert_day = None
    last_hourly_alert_hour = None
    
    cycle_count = 0
    parallel_failures = 0
    max_parallel_failures = 3  # Fallback después de 3 fallos consecutivos
    
    while True:
        try:
            cycle_count += 1
            cycle_start = time.time()
            log(f"🔄 Iniciando ciclo de monitoreo #{cycle_count}")
            
            # Decidir qué sistema usar
            monitoring_success = False
            
            if use_parallel and parallel_failures < max_parallel_failures:
                try:
                    check_and_alert_parallel()
                    monitoring_success = True
                    parallel_failures = 0  # Reset contador en éxito
                    
                except Exception as e:
                    parallel_failures += 1
                    log(f"❌ Error en monitoreo paralelo (intento {parallel_failures}/{max_parallel_failures}): {e}")
                    
                    if parallel_failures >= max_parallel_failures:
                        log("⚠️ Desactivando monitoreo paralelo por fallos consecutivos")
                        use_parallel = False
            
            # Fallback al sistema secuencial si el paralelo falló
            if not monitoring_success:
                log("🔄 Ejecutando monitoreo secuencial...")
                check_and_alert_sequential()
            
            cycle_duration = time.time() - cycle_start
            log(f"✅ Ciclo #{cycle_count} completado en {cycle_duration:.1f}s")
            
            # Verifica si es hora de enviar reporte de conteo (7am/7pm)
            now = datetime.now()
            current_hour = now.strftime("%H:%M")
            current_day = now.strftime("%Y-%m-%d")
            
            if current_hour in REPORT_TIMES:
                if last_report_day != current_day or last_report_hour != current_hour:
                    log("📧 Enviando reporte programado...")
                    send_vm_report()
                    last_report_day = current_day
                    last_report_hour = current_hour
            
            # Verifica si es hora de enviar reporte horario de alertas (cada hora en punto)
            if should_send_hourly_alert_report():
                current_hour_only = now.strftime("%H")
                if last_hourly_alert_day != current_day or last_hourly_alert_hour != current_hour_only:
                    log("📧 Enviando reporte horario...")
                    send_hourly_alert_report()
                    last_hourly_alert_day = current_day
                    last_hourly_alert_hour = current_hour_only
            
            log(f"⏱️ Esperando {CHECK_INTERVAL}s hasta próximo ciclo...")
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            log("🛑 Deteniendo vm-monitoring por interrupción del usuario")
            break
        except Exception as e:
            log(f"❌ Error en loop principal (ciclo #{cycle_count}): {e}")
            log("⏱️ Continuando después de error...")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
