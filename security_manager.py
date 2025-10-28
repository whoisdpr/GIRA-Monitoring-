#!/usr/bin/env python3
"""
Security Manager - Sistema de seguridad para VM Monitor

Este módulo proporciona:
- Cifrado/descifrado de credenciales sensibles
- Manejo seguro de configuración externa
- Soporte para autenticación SSH con claves
- Gestión de secretos con permisos apropiados
"""

import os
import base64
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecurityManager:
    """Gestor de seguridad para credenciales y configuración"""
    
    def __init__(self, config_file: str = "config.env", master_key_file: str = ".master_key"):
        """
        Inicializa el gestor de seguridad
        
        Args:
            config_file: Archivo de configuración
            master_key_file: Archivo de clave maestra
        """
        self.config_file = config_file
        self.master_key_file = master_key_file
        self.logger = logging.getLogger('security_manager')
        
        # Inicializar sistema de cifrado
        self.cipher = self._initialize_encryption()
        
        # Cargar configuración
        self.config = self._load_configuration()
    
    def _initialize_encryption(self) -> Fernet:
        """Inicializa el sistema de cifrado con clave maestra"""
        try:
            if os.path.exists(self.master_key_file):
                # Cargar clave existente
                with open(self.master_key_file, 'rb') as f:
                    key = f.read()
                self.logger.info("🔑 Clave maestra cargada")
            else:
                # Generar nueva clave maestra
                key = Fernet.generate_key()
                with open(self.master_key_file, 'wb') as f:
                    f.write(key)
                
                # Establecer permisos restrictivos (solo owner)
                os.chmod(self.master_key_file, 0o600)
                self.logger.info("🔑 Nueva clave maestra generada")
            
            return Fernet(key)
            
        except Exception as e:
            self.logger.error(f"❌ Error inicializando cifrado: {e}")
            raise
    
    def _load_configuration(self) -> Dict[str, str]:
        """Carga configuración desde archivo .env"""
        config = {}
        
        if not os.path.exists(self.config_file):
            self.logger.warning(f"⚠️ Archivo de configuración {self.config_file} no encontrado")
            return config
        
        try:
            with open(self.config_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Ignorar comentarios y líneas vacías
                    if line.startswith('#') or not line:
                        continue
                    
                    # Parsear clave=valor
                    if '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
                    else:
                        self.logger.warning(f"⚠️ Línea malformada en {self.config_file}:{line_num}: {line}")
            
            self.logger.info(f"✅ Configuración cargada: {len(config)} parámetros")
            return config
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando configuración: {e}")
            return {}
    
    def encrypt_value(self, plaintext: str) -> str:
        """
        Cifra un valor y lo marca como cifrado
        
        Args:
            plaintext: Texto plano a cifrar
            
        Returns:
            Valor cifrado con prefijo 'encrypted:'
        """
        try:
            encrypted_bytes = self.cipher.encrypt(plaintext.encode('utf-8'))
            encrypted_str = base64.b64encode(encrypted_bytes).decode('utf-8')
            return f"encrypted:{encrypted_str}"
            
        except Exception as e:
            self.logger.error(f"❌ Error cifrando valor: {e}")
            raise
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """
        Descifra un valor cifrado
        
        Args:
            encrypted_value: Valor cifrado con prefijo 'encrypted:'
            
        Returns:
            Texto plano descifrado
        """
        try:
            if not encrypted_value.startswith("encrypted:"):
                # No está cifrado, retornar tal como está
                return encrypted_value
            
            # Remover prefijo y descifrar
            encrypted_str = encrypted_value[10:]  # Remover "encrypted:"
            encrypted_bytes = base64.b64decode(encrypted_str.encode('utf-8'))
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"❌ Error descifrando valor: {e}")
            raise
    
    def get_config_value(self, key: str, default: Optional[str] = None, decrypt: bool = True) -> Optional[str]:
        """
        Obtiene valor de configuración, descifrando si es necesario
        
        Args:
            key: Clave de configuración
            default: Valor por defecto
            decrypt: Si debe descifrar automáticamente
            
        Returns:
            Valor de configuración (descifrado si aplica)
        """
        value = self.config.get(key, default)
        
        if value is None:
            return None
        
        if decrypt and value.startswith("encrypted:"):
            return self.decrypt_value(value)
        
        return value
    
    def set_config_value(self, key: str, value: str, encrypt: bool = False):
        """
        Establece valor de configuración, cifrando si se solicita
        
        Args:
            key: Clave de configuración
            value: Valor a establecer
            encrypt: Si debe cifrar el valor
        """
        if encrypt:
            value = self.encrypt_value(value)
        
        self.config[key] = value
    
    def save_configuration(self):
        """Guarda la configuración actual al archivo"""
        try:
            # Crear backup del archivo existente
            if os.path.exists(self.config_file):
                backup_file = f"{self.config_file}.backup"
                os.rename(self.config_file, backup_file)
                self.logger.info(f"📄 Backup creado: {backup_file}")
            
            # Escribir nueva configuración
            with open(self.config_file, 'w') as f:
                f.write("# Configuración del Sistema de Monitoreo VM\n")
                f.write("# ==========================================\n")
                f.write("# Generado automáticamente - NO editar manualmente\n\n")
                
                # Agrupar configuración por categorías
                categories = {
                    'SSH': ['SSH_USER', 'SSH_PASS', 'SSH_KEY_PATH'],
                    'EMAIL': ['EMAIL_FROM', 'EMAIL_PASS', 'EMAIL_TO', 'SMTP_SERVER', 'SMTP_PORT'],
                    'WORKERS': ['WORKERS'],
                    'MONITORING': ['CHECK_INTERVAL', 'A_MODERATE_MAX', 'A_HIGH_MAX'],
                    'FILES': ['DB_FILE', 'LOG_FILE', 'PID_FILE'],
                    'REPORTS': ['REPORT_TIMES']
                }
                
                for category, keys in categories.items():
                    f.write(f"# {category} Configuration\n")
                    for key in keys:
                        if key in self.config:
                            f.write(f"{key}={self.config[key]}\n")
                    f.write("\n")
                
                # Escribir cualquier clave adicional
                written_keys = set()
                for keys in categories.values():
                    written_keys.update(keys)
                
                additional_keys = set(self.config.keys()) - written_keys
                if additional_keys:
                    f.write("# Additional Configuration\n")
                    for key in sorted(additional_keys):
                        f.write(f"{key}={self.config[key]}\n")
            
            # Establecer permisos restrictivos
            os.chmod(self.config_file, 0o600)
            self.logger.info(f"✅ Configuración guardada en {self.config_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Error guardando configuración: {e}")
            raise


class SSHAuthManager:
    """Gestor de autenticación SSH con soporte para claves y contraseñas"""
    
    def __init__(self, security_manager: SecurityManager):
        """
        Inicializa el gestor de autenticación SSH
        
        Args:
            security_manager: Instancia del gestor de seguridad
        """
        self.security = security_manager
        self.logger = logging.getLogger('ssh_auth_manager')
        
        # Configuración SSH
        self.ssh_user = self.security.get_config_value('SSH_USER', 'stack')
        self.ssh_pass = self.security.get_config_value('SSH_PASS')
        self.ssh_key_path = self.security.get_config_value('SSH_KEY_PATH')
        
        # Determinar método de autenticación preferido
        self.auth_method = self._determine_auth_method()
    
    def _determine_auth_method(self) -> str:
        """Determina el método de autenticación SSH a usar"""
        # Prioridad: 1. Clave SSH, 2. Contraseña
        if self.ssh_key_path and os.path.exists(self.ssh_key_path):
            # Verificar permisos de la clave privada
            key_stat = os.stat(self.ssh_key_path)
            if key_stat.st_mode & 0o077:
                self.logger.warning(f"⚠️ Clave SSH {self.ssh_key_path} tiene permisos inseguros")
            
            self.logger.info(f"🔑 Usando autenticación por clave SSH: {self.ssh_key_path}")
            return 'key'
        
        elif self.ssh_pass:
            self.logger.info("🔒 Usando autenticación por contraseña")
            return 'password'
        
        else:
            self.logger.error("❌ No se encontró método de autenticación SSH válido")
            raise ValueError("No SSH authentication method available")
    
    def build_ssh_command(self, host: str, command: str, timeout: int = 30) -> list:
        """
        Construye comando SSH según el método de autenticación
        
        Args:
            host: Host destino
            command: Comando a ejecutar
            timeout: Timeout de conexión
            
        Returns:
            Lista con comando SSH completo
        """
        connect_timeout = min(timeout // 3, 10)
        
        base_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            "-o", "BatchMode=yes"
        ]
        
        if self.auth_method == 'key':
            # Autenticación por clave
            base_cmd.extend([
                "-i", self.ssh_key_path,
                "-o", "PasswordAuthentication=no"
            ])
            ssh_cmd = base_cmd + [f"{self.ssh_user}@{host}", command]
            
        elif self.auth_method == 'password':
            # Autenticación por contraseña
            ssh_cmd = [
                "sshpass", "-p", self.ssh_pass
            ] + base_cmd + [
                "-o", "PasswordAuthentication=yes",
                f"{self.ssh_user}@{host}",
                command
            ]
        
        else:
            raise ValueError(f"Método de autenticación no soportado: {self.auth_method}")
        
        return ssh_cmd
    
    def test_authentication(self, host: str) -> bool:
        """
        Prueba la autenticación SSH a un host
        
        Args:
            host: Host a probar
            
        Returns:
            True si la autenticación es exitosa
        """
        try:
            import subprocess
            
            cmd = self.build_ssh_command(host, "echo 'auth_test'", timeout=10)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            success = result.returncode == 0 and 'auth_test' in result.stdout
            
            if success:
                self.logger.info(f"✅ Autenticación SSH exitosa a {host}")
            else:
                self.logger.error(f"❌ Fallo autenticación SSH a {host}: {result.stderr}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"❌ Error probando autenticación a {host}: {e}")
            return False


def create_security_manager(config_file: str = "config.env") -> SecurityManager:
    """
    Función de conveniencia para crear gestor de seguridad
    
    Args:
        config_file: Archivo de configuración
        
    Returns:
        Instancia configurada de SecurityManager
    """
    return SecurityManager(config_file)


if __name__ == "__main__":
    # Demo del sistema de seguridad
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    print("🔐 DEMO DEL SISTEMA DE SEGURIDAD")
    print("=" * 40)
    
    # Crear gestor de seguridad
    security = create_security_manager("demo_config.env")
    
    # Cifrar algunas credenciales de ejemplo
    print("\n1️⃣ Cifrando credenciales...")
    encrypted_password = security.encrypt_value("mi_password_secreto")
    encrypted_email_pass = security.encrypt_value("app_password_gmail")
    
    print(f"  Password cifrado: {encrypted_password[:30]}...")
    print(f"  Email pass cifrado: {encrypted_email_pass[:30]}...")
    
    # Establecer configuración
    print("\n2️⃣ Estableciendo configuración...")
    security.set_config_value("SSH_USER", "stack")
    security.set_config_value("SSH_PASS", "mi_password_secreto", encrypt=True)
    security.set_config_value("EMAIL_PASS", "app_password_gmail", encrypt=True)
    security.set_config_value("WORKERS", "hast-wn1,hast-wn2,hast-wn3")
    
    # Guardar configuración
    security.save_configuration()
    print("  ✅ Configuración guardada")
    
    # Probar descifrado
    print("\n3️⃣ Probando descifrado...")
    decrypted_pass = security.get_config_value("SSH_PASS")
    print(f"  Password descifrado: {decrypted_pass}")
    
    # Probar autenticación SSH
    print("\n4️⃣ Probando autenticación SSH...")
    auth_manager = SSHAuthManager(security)
    print(f"  Método: {auth_manager.auth_method}")
    print(f"  Usuario: {auth_manager.ssh_user}")
    
    print("\n🎉 Demo completado")