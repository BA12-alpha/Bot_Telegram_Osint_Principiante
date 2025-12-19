# 🎓 CyberMentor Bot - Bot Educativo de Ciberseguridad

Bot de Telegram interactivo que actúa como profesor virtual de ciberseguridad, guiando a los usuarios desde nivel principiante hasta experto mediante un sistema estructurado de aprendizaje adaptativo.

## 🌟 Características Principales

### Sistema de Aprendizaje
- **Curriculum Estructurado**: 5 módulos progresivos desde fundamentos hasta especializaciones avanzadas
- **Seguimiento de Progreso**: Base de datos SQLite para persistencia de datos de usuario
- **Sistema de XP y Niveles**: Gamificación con experiencia, logros y niveles
- **Adaptación por Dispositivo**: Experiencia optimizada para smartphone y computadora
- **Lecciones Interactivas**: Contenido teórico con preguntas de comprensión

### Módulos de Aprendizaje

#### A. Fundamentos (0-20%)
- Introducción a la Ciberseguridad
- Tipos de Amenazas
- Contraseñas Seguras
- Autenticación Multifactor (MFA)
- Ética y Legalidad

#### B. Redes y Protocolos (21-40%)
- Fundamentos de Redes
- Análisis de Tráfico
- Protocolos de Seguridad
- DNS y Servicios de Red

#### C. Programación para Seguridad (41-60%)
- Python para Seguridad
- Prevención de Inyección SQL
- Desarrollo de Herramientas
- Análisis de Código

#### D. Pentesting y Hats (61-80%)
- Introducción al Pentesting
- Reconocimiento OSINT
- Técnicas de Explotación
- Post-Explotación

#### E. Especializaciones Avanzadas (81-100%)
- Análisis Forense Digital
- Respuesta a Incidentes
- Técnicas Avanzadas de Pentesting
- Arquitectura de Seguridad

### Herramientas OSINT
El bot mantiene todas las capacidades OSINT del bot original:
- **Análisis de IP**: Geolocalización, puertos abiertos, información de ISP
- **Análisis de Dominios**: WHOIS, DNS, subdominios, certificados SSL
- **Análisis de Email**: Validación, servidores MX, WHOIS del dominio
- **Análisis de URLs**: Detección de phishing y riesgos
- **Búsqueda en Redes Sociales**: Verificación de presencia en 9+ plataformas
- **Análisis de Imágenes**: Extracción de metadatos EXIF
- **Análisis de Contraseñas**: Evaluación de fortaleza
- **Cifrado Educativo**: Cifrado/descifrado con Fernet (AES)

### Especializaciones (Hats)
- **⚪ White Hat**: Hacking ético y defensa
- **⚫ Grey Hat**: Técnicas mixtas, bug bounty
- **🔵 Blue Hat**: Seguridad corporativa y SOC
- **🔴 Red Hat**: Operaciones ofensivas controladas
- **🔍 Forense Digital**: Investigación y análisis post-incidente

## 🚀 Instalación

### Requisitos
- Python 3.8+
- pip
- Token de Bot de Telegram

### Pasos de Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/BA12-alpha/Bot_Telegram_Osint_Principiante.git
cd Bot_Telegram_Osint_Principiante
```

2. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

3. **Configurar el bot**
```bash
cp config.example.json config.json
```

Edita `config.json` y añade tu token de Telegram:
```json
{
  "telegram": {
    "bot_token": "TU_TOKEN_AQUI"
  }
}
```

4. **Ejecutar el bot**
```bash
python bot_osint_seguro.py
```

## 📱 Comandos Disponibles

### Comandos de Aprendizaje
- `/start` - Iniciar o continuar aprendizaje
- `/leccion` - Ver lección actual
- `/ejercicio` - Solicitar ejercicio práctico
- `/entregar <respuesta>` - Entregar ejercicio
- `/progreso` - Ver tu progreso y estadísticas
- `/especialidad` - Ver especializaciones disponibles
- `/recursos` - Recursos adicionales de aprendizaje

### Comandos OSINT
- `/ip <ip>` - Análisis de dirección IP
- `/domain <dominio>` - Información de dominio (WHOIS, DNS)
- `/email <correo>` - Análisis de email
- `/url <url>` - Análisis de seguridad de URL
- `/ssl <dominio>` - Verificación de certificado SSL
- `/subdomains <dominio>` - Búsqueda de subdominios
- `/dns <dominio>` - Consulta de registros DNS
- `/phone <numero>` - Análisis de número telefónico
- `/social <usuario>` - Búsqueda en redes sociales
- `/image <url>` - Análisis de metadatos de imagen

### Comandos de Seguridad
- `/password <contraseña>` - Evaluar fortaleza de contraseña
- `/genpass <longitud>` - Generar contraseña segura
- `/hash <hash>` - Identificar tipo de hash
- `/analyze <cadena>` - Detectar formato (hash/base64/hex/url)
- `/encrypt <clave> <texto>` - Cifrar con Fernet (AES)
- `/decrypt <clave> <cifrado>` - Descifrar con Fernet

### Otros Comandos
- `/menu` - Ver menú principal
- `/help` - Ayuda general
- `/history` - Ver historial de búsquedas OSINT
- `/report <tipo> <valor>` - Generar reporte OSINT
- `/explain <tema>` - Explicación de conceptos (hash, ssl, 2fa, phishing)

## 🎮 Flujo de Usuario

### Primera Vez
1. Usuario envía `/start`
2. Bot da la bienvenida y pregunta dispositivo (📱 Smartphone / 💻 Computadora)
3. Bot crea perfil de usuario adaptado al dispositivo
4. Usuario comienza con Módulo A, Lección 1.1

### Usuario Recurrente
1. Usuario envía `/start`
2. Bot muestra progreso actual y última lección
3. Opciones para continuar o ver progreso

### Durante el Aprendizaje
1. Ver lección con `/leccion`
2. Responder preguntas de comprensión
3. Solicitar ejercicios con `/ejercicio`
4. Entregar soluciones con `/entregar`
5. Recibir feedback automático y XP
6. Marcar lección como completada
7. Avanzar a siguiente lección

## 🏆 Sistema de Gamificación

### Niveles
- **Beginner** (0-199 XP)
- **Intermediate** (200-499 XP)
- **Advanced** (500-999 XP)
- **Expert** (1000+ XP)

### XP por Actividad
- Completar lección: 50-120 XP
- Responder pregunta correcta: 10 XP
- Entregar ejercicio: 15-50 XP (según puntuación)

### Logros
- 🏅 Primera Lección Completada
- 🏅 Módulo A Completado
- 🏅 10 Lecciones Completadas
- 🏅 Experto en OSINT
- 🏅 Especialización Elegida

## 📊 Base de Datos

El bot usa SQLite para almacenar:
- **Perfiles de usuario**: ID, nivel, XP, módulo/lección actual
- **Progreso**: Lecciones completadas con puntuaciones
- **Ejercicios**: Entregas y feedback
- **Logros**: Logros desbloqueados
- **Especializaciones**: Hats seleccionados

## ⚠️ Consideraciones Éticas

El bot enfatiza constantemente:
- ✅ **Uso ético** de técnicas de seguridad
- ✅ **Autorización requerida** antes de realizar pentesting
- ✅ **Entornos controlados** para prácticas
- ✅ **Compliance legal** y responsabilidad
- ❌ **No practicar contra sistemas reales sin permiso**

## 🔒 Seguridad

- Sanitización de entradas
- Validación de datos de usuario
- Permisos de archivo restrictivos (0o700)
- Scrubbing de datos sensibles en logs
- Timeouts en requests HTTP
- No almacenamiento de contraseñas en texto plano

## 🛠️ Desarrollo

### Estructura del Proyecto
```
.
├── bot_osint_seguro.py    # Bot principal con handlers
├── database.py             # Módulo de base de datos
├── curriculum.py           # Contenido del curriculum
├── config.example.json     # Ejemplo de configuración
├── requirements.txt        # Dependencias Python
├── cybermentor.db         # Base de datos (generada)
├── results/               # Resultados de búsquedas OSINT
└── README.md              # Este archivo
```

### Agregar Nuevo Contenido

#### Nueva Lección
Edita `curriculum.py` y añade en `_init_lessons()`:
```python
"X.Y": {
    "module": "X",
    "title": "Título de la Lección",
    "content": "Contenido markdown...",
    "questions": [
        {
            "q": "Pregunta",
            "options": ["A", "B", "C", "D"],
            "answer": 0
        }
    ],
    "xp": 50
}
```

#### Nuevo Ejercicio
Añade en `_init_exercises()`:
```python
"EX.Y": {
    "lesson": "X.Y",
    "title": "Título del Ejercicio",
    "description": "Descripción...",
    "type": "code|practical|multiple_choice",
    "xp": 40
}
```

## 📝 Licencia

Este proyecto mantiene la licencia original del repositorio.

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor:
1. Fork el repositorio
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Crea un Pull Request

## 📧 Soporte

Para reportar bugs o sugerir features, abre un issue en GitHub.

## 🙏 Agradecimientos

- Basado en el bot OSINT original de ciberseguridad
- Comunidad de seguridad informática
- Contribuidores del proyecto

---

**⚠️ DESCARGO DE RESPONSABILIDAD**: Este bot es solo para fines educativos. Los usuarios son responsables del uso ético y legal de las técnicas aprendidas.
