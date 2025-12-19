#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Curriculum module for CyberMentor Bot
Contains lessons, exercises, and learning content
"""

from typing import Dict, List, Optional, Any


class Curriculum:
    """Manages the cybersecurity curriculum"""

    def __init__(self):
        self.modules = self._init_modules()
        self.lessons = self._init_lessons()
        self.exercises = self._init_exercises()
        self.specializations = self._init_specializations()

    def _init_modules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize curriculum modules"""
        return {
            "A": {
                "name": "Fundamentos",
                "progress_range": (0, 20),
                "description": "Conceptos básicos de ciberseguridad",
                "lessons": ["1.1", "1.2", "1.3", "1.4", "1.5"]
            },
            "B": {
                "name": "Redes y Protocolos",
                "progress_range": (21, 40),
                "description": "Fundamentos de redes y comunicación",
                "lessons": ["2.1", "2.2", "2.3", "2.4", "2.5"]
            },
            "C": {
                "name": "Programación para Seguridad",
                "progress_range": (41, 60),
                "description": "Desarrollo de herramientas de seguridad",
                "lessons": ["3.1", "3.2", "3.3", "3.4", "3.5"]
            },
            "D": {
                "name": "Pentesting y Hats",
                "progress_range": (61, 80),
                "description": "Técnicas de pentesting ético",
                "lessons": ["4.1", "4.2", "4.3", "4.4", "4.5"]
            },
            "E": {
                "name": "Especializaciones Avanzadas",
                "progress_range": (81, 100),
                "description": "Temas avanzados y especializados",
                "lessons": ["5.1", "5.2", "5.3", "5.4", "5.5"]
            }
        }

    def _init_lessons(self) -> Dict[str, Dict[str, Any]]:
        """Initialize lesson content"""
        return {
            # Module A: Fundamentos
            "1.1": {
                "module": "A",
                "title": "Introducción a la Ciberseguridad",
                "content": """
*🎯 Lección 1.1: Introducción a la Ciberseguridad*

La ciberseguridad es la práctica de proteger sistemas, redes y datos de ataques digitales.

*Conceptos clave:*
• Confidencialidad: Solo usuarios autorizados acceden a la información
• Integridad: Los datos no son modificados sin autorización
• Disponibilidad: Los sistemas están accesibles cuando se necesitan

*Triada CIA:*
Estos tres principios (Confidentiality, Integrity, Availability) forman la base de la seguridad.

*¿Por qué es importante?*
• Protección de datos personales
• Seguridad empresarial
• Prevención de fraudes
• Cumplimiento legal
                """,
                "questions": [
                    {
                        "q": "¿Qué significa la 'C' en la triada CIA?",
                        "options": ["Confidencialidad", "Ciberseguridad", "Control", "Cifrado"],
                        "answer": 0
                    }
                ],
                "xp": 50
            },
            "1.2": {
                "module": "A",
                "title": "Tipos de Amenazas",
                "content": """
*🎯 Lección 1.2: Tipos de Amenazas*

*Principales amenazas de ciberseguridad:*

• *Malware:* Software malicioso (virus, ransomware, troyanos)
• *Phishing:* Engaño para robar credenciales
• *Ataques DDoS:* Saturación de servicios
• *Ingeniería Social:* Manipulación psicológica
• *Ataques de Fuerza Bruta:* Prueba exhaustiva de contraseñas

*Ejemplos reales:*
• Ransomware WannaCry (2017)
• Phishing masivo contra empresas
• Filtraciones de datos personales

⚠️ *Importante:* Entender las amenazas es el primer paso para defenderse.
                """,
                "questions": [
                    {
                        "q": "¿Qué tipo de ataque busca engañar al usuario para robar credenciales?",
                        "options": ["DDoS", "Phishing", "Malware", "Brute Force"],
                        "answer": 1
                    }
                ],
                "xp": 50
            },
            "1.3": {
                "module": "A",
                "title": "Contraseñas Seguras",
                "content": """
*🎯 Lección 1.3: Contraseñas Seguras*

*Características de una contraseña fuerte:*
• Mínimo 12-16 caracteres
• Combina mayúsculas, minúsculas, números y símbolos
• No usa palabras del diccionario
• Única para cada servicio

*Malas prácticas:*
❌ password123
❌ qwerty
❌ Tu nombre o fecha de nacimiento
❌ Reutilizar contraseñas

*Buenas prácticas:*
✅ Usar un gestor de contraseñas
✅ Activar autenticación de dos factores (2FA)
✅ Cambiar contraseñas comprometidas
✅ Usar frases de contraseña: "Café-Azul-Montaña-2024!"

*Ejercicio práctico:*
Usa el comando `/password` del bot para verificar la fortaleza de tus contraseñas.
                """,
                "questions": [
                    {
                        "q": "¿Cuál es la longitud mínima recomendada para una contraseña?",
                        "options": ["6 caracteres", "8 caracteres", "12 caracteres", "20 caracteres"],
                        "answer": 2
                    }
                ],
                "xp": 50
            },
            "1.4": {
                "module": "A",
                "title": "Autenticación Multifactor (MFA)",
                "content": """
*🎯 Lección 1.4: Autenticación Multifactor*

*¿Qué es MFA/2FA?*
Autenticación de múltiples factores añade capas adicionales de seguridad más allá de la contraseña.

*Factores de autenticación:*
1. *Algo que sabes:* Contraseña, PIN
2. *Algo que tienes:* Teléfono, token USB, tarjeta
3. *Algo que eres:* Huella, rostro, iris

*Métodos comunes de 2FA:*
• Códigos SMS (menos seguro)
• Apps de autenticación (Google Authenticator, Authy)
• Llaves de seguridad USB (YubiKey)
• Notificaciones push

*Ventajas:*
✅ Protección incluso si roban tu contraseña
✅ Alerta temprana de intentos de acceso
✅ Cumplimiento de normativas

⚠️ *Recomendación:* Activa 2FA en todas tus cuentas importantes.
                """,
                "questions": [
                    {
                        "q": "¿Cuál es el método más seguro de 2FA?",
                        "options": ["SMS", "Apps de autenticación", "Llaves USB físicas", "Email"],
                        "answer": 2
                    }
                ],
                "xp": 60
            },
            "1.5": {
                "module": "A",
                "title": "Ética y Legalidad en Ciberseguridad",
                "content": """
*🎯 Lección 1.5: Ética y Legalidad*

*Principios éticos del hacker ético:*
• Obtener SIEMPRE autorización por escrito
• Respetar la privacidad
• Reportar vulnerabilidades responsablemente
• No causar daño
• Mantener confidencialidad

*Marco legal:*
• Acceso no autorizado = DELITO
• Leyes varían por país
• Consecuencias: multas, cárcel, antecedentes

*Hacking Ético vs Criminal:*
• *Ético:* Autorizado, documentado, para mejorar seguridad
• *Criminal:* Sin permiso, con intención maliciosa

*Bug Bounty Programs:*
Empresas pagan por reportar vulnerabilidades:
• HackerOne
• Bugcrowd
• Intigriti

⚠️ *IMPORTANTE:* Las técnicas que aprenderás SOLO deben usarse en:
• Tu propio equipo/red
• Entornos autorizados
• Laboratorios de práctica
• Programas de bug bounty con autorización
                """,
                "questions": [
                    {
                        "q": "¿Qué es lo PRIMERO que necesitas antes de realizar un pentest?",
                        "options": ["Herramientas", "Conocimientos técnicos", "Autorización por escrito", "Un equipo"],
                        "answer": 2
                    }
                ],
                "xp": 60
            },
            # Module B: Redes y Protocolos
            "2.1": {
                "module": "B",
                "title": "Fundamentos de Redes",
                "content": """
*🎯 Lección 2.1: Fundamentos de Redes*

*Modelo OSI (7 capas):*
7. Aplicación - HTTP, FTP, SMTP
6. Presentación - Cifrado, compresión
5. Sesión - Establecimiento de conexiones
4. Transporte - TCP, UDP
3. Red - IP, enrutamiento
2. Enlace de datos - Ethernet, Wi-Fi
1. Física - Cables, señales

*Protocolos importantes:*
• *TCP:* Confiable, orientado a conexión
• *UDP:* Rápido, sin garantías
• *IP:* Direccionamiento (IPv4, IPv6)
• *DNS:* Resolución de nombres

*Direcciones IP:*
• IPv4: 192.168.1.1 (32 bits)
• IPv6: 2001:0db8:85a3::8a2e:0370:7334 (128 bits)
• Públicas vs Privadas

*Puertos comunes:*
• 80: HTTP
• 443: HTTPS
• 22: SSH
• 21: FTP
• 25: SMTP
                """,
                "questions": [
                    {
                        "q": "¿Qué puerto usa HTTPS?",
                        "options": ["80", "443", "22", "8080"],
                        "answer": 1
                    }
                ],
                "xp": 70
            },
            "2.2": {
                "module": "B",
                "title": "Análisis de Tráfico",
                "content": """
*🎯 Lección 2.2: Análisis de Tráfico*

*¿Qué es el análisis de tráfico?*
Inspección de datos que fluyen por una red para detectar problemas o amenazas.

*Herramientas principales:*
• *Wireshark:* Captura y análisis de paquetes
• *tcpdump:* Captura de línea de comandos
• *Zeek:* Análisis de seguridad

*Conceptos clave:*
• *Sniffer:* Captura tráfico de red
• *Filtros:* Seleccionar tráfico específico
• *Deep Packet Inspection:* Análisis detallado

*Casos de uso:*
• Detección de malware
• Investigación forense
• Optimización de red
• Detección de intrusiones

*Ejemplo de filtro Wireshark:*
```
http.request.method == "POST"
ip.addr == 192.168.1.100
tcp.port == 443
```

⚠️ *Nota legal:* Solo captura tráfico de redes donde tengas autorización.
                """,
                "questions": [
                    {
                        "q": "¿Qué herramienta es más usada para análisis de paquetes?",
                        "options": ["Nmap", "Wireshark", "Metasploit", "Burp Suite"],
                        "answer": 1
                    }
                ],
                "xp": 70
            },
            # Module C: Programación para Seguridad
            "3.1": {
                "module": "C",
                "title": "Python para Seguridad",
                "content": """
*🎯 Lección 3.1: Python para Seguridad*

*¿Por qué Python?*
• Sintaxis simple
• Librerías de seguridad
• Automatización
• Comunidad activa

*Librerías esenciales:*
• *requests:* HTTP requests
• *socket:* Conexiones de red
• *scapy:* Manipulación de paquetes
• *paramiko:* SSH
• *cryptography:* Cifrado

*Ejemplo: Scanner de puertos básico*
```python
import socket

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

# Uso
if scan_port("127.0.0.1", 80):
    print("Puerto 80 abierto")
```

*Ejercicio:* Modifica el código para escanear múltiples puertos.
                """,
                "questions": [
                    {
                        "q": "¿Qué librería de Python se usa para manipular paquetes de red?",
                        "options": ["requests", "scapy", "flask", "django"],
                        "answer": 1
                    }
                ],
                "xp": 80
            },
            "3.2": {
                "module": "C",
                "title": "Prevención de Inyección SQL",
                "content": """
*🎯 Lección 3.2: Prevención de Inyección SQL*

*¿Qué es SQL Injection?*
Vulnerabilidad que permite ejecutar comandos SQL maliciosos en una base de datos.

*Ejemplo vulnerable:*
```python
# ❌ INSEGURO
query = f"SELECT * FROM users WHERE id = {user_id}"
```

*Ataque:*
```
user_id = "1 OR 1=1"
# Resultado: SELECT * FROM users WHERE id = 1 OR 1=1
# Retorna TODOS los usuarios
```

*Prevención - Consultas Parametrizadas:*
```python
# ✅ SEGURO
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

*Otras medidas:*
• Validar entrada del usuario
• Limitar privilegios de BD
• Usar ORMs (SQLAlchemy, Django ORM)
• Escapar caracteres especiales
• Preparar statements

*Ejercicio práctico:*
Identifica la vulnerabilidad en este código:
```python
username = input("Usuario: ")
password = input("Password: ")
query = f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"
```

*Respuesta:* Un atacante podría usar: `admin' --` como username.
                """,
                "questions": [
                    {
                        "q": "¿Cuál es la mejor defensa contra SQL Injection?",
                        "options": ["Validar longitud", "Usar consultas parametrizadas", "Cifrar la BD", "Usar HTTPS"],
                        "answer": 1
                    }
                ],
                "xp": 90
            },
            # Module D: Pentesting
            "4.1": {
                "module": "D",
                "title": "Introducción al Pentesting",
                "content": """
*🎯 Lección 4.1: Introducción al Pentesting*

*¿Qué es Pentesting?*
Pruebas de penetración: simulación de ataques para encontrar vulnerabilidades.

*Fases del Pentesting:*
1. *Reconocimiento:* Recopilación de información
2. *Escaneo:* Identificar sistemas y servicios
3. *Explotación:* Aprovechar vulnerabilidades
4. *Post-explotación:* Mantener acceso, escalar privilegios
5. *Reporte:* Documentar hallazgos y recomendaciones

*Tipos de Pentesting:*
• *Black Box:* Sin información previa
• *White Box:* Con información completa
• *Grey Box:* Información parcial

*Herramientas principales:*
• Nmap: Escaneo de redes
• Metasploit: Framework de explotación
• Burp Suite: Testing de aplicaciones web
• Wireshark: Análisis de red

⚠️ *RECORDATORIO:* Solo en entornos autorizados.
                """,
                "questions": [
                    {
                        "q": "¿Cuál es la primera fase del pentesting?",
                        "options": ["Explotación", "Reconocimiento", "Escaneo", "Reporte"],
                        "answer": 1
                    }
                ],
                "xp": 100
            },
            "4.2": {
                "module": "D",
                "title": "Reconocimiento OSINT",
                "content": """
*🎯 Lección 4.2: Reconocimiento OSINT*

*OSINT (Open Source Intelligence):*
Recopilación de información de fuentes públicas.

*Tipos de información:*
• Nombres de dominio
• Direcciones IP
• Empleados y correos
• Tecnologías usadas
• Redes sociales
• Registros públicos

*Herramientas OSINT:*
• *theHarvester:* Recopilación de emails y subdominios
• *Maltego:* Mapeo de relaciones
• *Shodan:* Motor de búsqueda de dispositivos
• *WHOIS:* Información de dominios

*Comandos útiles:*
```bash
# DNS lookup
nslookup example.com

# WHOIS
whois example.com

# Subdominios
sublist3r -d example.com
```

*Práctica con este bot:*
• `/domain` - Información de dominio
• `/ip` - Análisis de IP
• `/email` - Análisis de email
• `/social` - Búsqueda en redes

*Ejercicio:*
Usa los comandos del bot para realizar reconocimiento de un dominio público.
                """,
                "questions": [
                    {
                        "q": "¿Qué significa OSINT?",
                        "options": ["Open System Intelligence", "Open Source Intelligence", "Online Security Intelligence", "Operating System Intelligence"],
                        "answer": 1
                    }
                ],
                "xp": 90
            },
            # Module E: Especializaciones
            "5.1": {
                "module": "E",
                "title": "Análisis Forense Digital",
                "content": """
*🎯 Lección 5.1: Análisis Forense Digital*

*¿Qué es el análisis forense?*
Investigación de incidentes de seguridad para determinar qué, cómo y quién.

*Principios fundamentales:*
• Cadena de custodia
• Integridad de evidencia
• Documentación meticulosa
• Análisis reproducible

*Áreas de análisis:*
• Forense de disco
• Forense de red
• Forense de memoria
• Análisis de malware

*Herramientas:*
• Autopsy: Análisis de disco
• Volatility: Análisis de memoria
• Wireshark: Análisis de red
• FTK Imager: Adquisición de evidencia

*Proceso típico:*
1. Preservación de evidencia
2. Adquisición de datos
3. Análisis
4. Documentación
5. Presentación de hallazgos

*Habilidades requeridas:*
• Conocimiento de sistemas operativos
• Análisis de logs
• Comprensión de ataques
• Habilidades legales
                """,
                "questions": [
                    {
                        "q": "¿Qué es lo más importante en análisis forense?",
                        "options": ["Velocidad", "Integridad de evidencia", "Costo", "Herramientas"],
                        "answer": 1
                    }
                ],
                "xp": 120
            }
        }

    def _init_exercises(self) -> Dict[str, Dict[str, Any]]:
        """Initialize exercises"""
        return {
            "E1.1": {
                "lesson": "1.1",
                "title": "Identifica la Triada CIA",
                "description": "Clasifica los siguientes escenarios según el principio de la triada CIA que protegen.",
                "type": "multiple_choice",
                "scenarios": [
                    "Un servidor web está disponible 24/7",
                    "Los datos están cifrados en tránsito",
                    "Los logs no pueden ser modificados"
                ],
                "xp": 30
            },
            "E1.3": {
                "lesson": "1.3",
                "title": "Crea una contraseña segura",
                "description": "Genera una contraseña que cumpla con los criterios aprendidos y verifica su fortaleza con `/password`.",
                "type": "practical",
                "requirements": [
                    "Mínimo 12 caracteres",
                    "Mayúsculas y minúsculas",
                    "Números y símbolos",
                    "Puntuación >= 4"
                ],
                "xp": 40
            },
            "E3.2": {
                "lesson": "3.2",
                "title": "Corrige código vulnerable",
                "description": """
Corrige este código vulnerable a SQL Injection:

```python
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)
```

Envía tu código corregido.
                """,
                "type": "code",
                "xp": 60
            }
        }

    def _init_specializations(self) -> Dict[str, Dict[str, str]]:
        """Initialize specializations (hats)"""
        return {
            "white_hat": {
                "name": "White Hat",
                "icon": "⚪",
                "description": "Hacker ético enfocado en defensa y protección de sistemas",
                "skills": "Auditorías de seguridad, pentesting ético, compliance"
            },
            "grey_hat": {
                "name": "Grey Hat",
                "icon": "⚫",
                "description": "Especialista en técnicas mixtas de seguridad",
                "skills": "Bug bounty, research, análisis de vulnerabilidades"
            },
            "blue_hat": {
                "name": "Blue Hat",
                "icon": "🔵",
                "description": "Especialista en seguridad corporativa y defensa",
                "skills": "SOC, SIEM, respuesta a incidentes, threat hunting"
            },
            "red_hat": {
                "name": "Red Hat",
                "icon": "🔴",
                "description": "Especialista en operaciones ofensivas controladas",
                "skills": "Red team, adversary simulation, explotación avanzada"
            },
            "forense": {
                "name": "Forense Digital",
                "icon": "🔍",
                "description": "Especialista en investigación y análisis post-incidente",
                "skills": "Análisis forense, recuperación de evidencia, informes periciales"
            }
        }

    def get_lesson(self, lesson_id: str) -> Optional[Dict[str, Any]]:
        """Get lesson by ID"""
        return self.lessons.get(lesson_id)

    def get_module(self, module_id: str) -> Optional[Dict[str, Any]]:
        """Get module by ID"""
        return self.modules.get(module_id)

    def get_exercise(self, exercise_id: str) -> Optional[Dict[str, Any]]:
        """Get exercise by ID"""
        return self.exercises.get(exercise_id)

    def get_next_lesson(self, current_lesson: str) -> Optional[str]:
        """Get next lesson ID"""
        # Extract module and lesson number
        try:
            parts = current_lesson.split(".")
            module_num = int(parts[0])
            lesson_num = int(parts[1])
            
            # Try next lesson in same module
            next_lesson = f"{module_num}.{lesson_num + 1}"
            if next_lesson in self.lessons:
                return next_lesson
            
            # Try first lesson of next module
            next_module = f"{module_num + 1}.1"
            if next_module in self.lessons:
                return next_module
            
            return None
        except:
            return None

    def calculate_progress(self, completed_lessons: List[str]) -> int:
        """Calculate overall progress percentage"""
        if not self.lessons:
            return 0
        total_lessons = len(self.lessons)
        completed_count = len(completed_lessons)
        return min(100, int((completed_count / total_lessons) * 100))

    def get_module_lessons(self, module_id: str) -> List[str]:
        """Get all lesson IDs for a module"""
        module = self.modules.get(module_id)
        if not module:
            return []
        return module.get("lessons", [])

    def get_specialization(self, spec_id: str) -> Optional[Dict[str, str]]:
        """Get specialization info"""
        return self.specializations.get(spec_id)

    def get_all_specializations(self) -> Dict[str, Dict[str, str]]:
        """Get all specializations"""
        return self.specializations
