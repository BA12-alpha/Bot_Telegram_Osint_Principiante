# 📖 Guía de Uso - CyberMentor Bot

## 🚀 Primeros Pasos

### 1. Iniciar el Bot
Busca el bot en Telegram y envía:
```
/start
```

### 2. Primera Configuración
El bot te preguntará:
> ¿Desde qué dispositivo estudiarás principalmente?

Opciones:
- **📱 Smartphone**: Lecciones más cortas, optimizadas para pantallas pequeñas
- **💻 Computadora**: Contenido más extenso, ejercicios de laboratorio

### 3. Tu Perfil
El bot creará automáticamente:
- **User ID**: Tu identificador único
- **Dispositivo**: El que seleccionaste
- **Nivel**: Principiante
- **XP**: 0 puntos
- **Módulo actual**: A - Fundamentos
- **Lección actual**: 1.1

## 📚 Aprendiendo con CyberMentor

### Ver Tu Lección Actual
```
/leccion
```
Muestra el contenido teórico de tu lección actual con:
- Explicación del tema
- Ejemplos prácticos
- Conceptos clave
- Botones para responder preguntas o completar

### Responder Preguntas
1. Dentro de una lección, pulsa el botón **❓ Pregunta**
2. Lee la pregunta de comprensión
3. Selecciona una respuesta
4. Recibe feedback inmediato:
   - ✅ **Correcto**: +10 XP
   - ❌ **Incorrecto**: Revisión recomendada

### Completar Lecciones
1. Lee toda la lección
2. Responde las preguntas (opcional pero recomendado)
3. Pulsa **✅ Completar lección**
4. Recibes:
   - +50-120 XP (según la lección)
   - Progreso guardado
   - Acceso a siguiente lección
   - Posibles logros desbloqueados 🏆

### Solicitar Ejercicios
```
/ejercicio
```
Muestra ejercicios prácticos relacionados con tu lección actual:
- Ejercicios de código
- Desafíos prácticos
- Análisis de casos

### Entregar Ejercicios
```
/entregar <tu_respuesta>
```

**Ejemplo**:
```
/entregar Mi contraseña segura es: Café-Montaña-2024!@#
```

El bot evaluará tu respuesta y te dará:
- Puntuación (0-100)
- Feedback específico
- XP proporcional a tu puntuación
- Opción para reintentar

## 📊 Seguimiento de Progreso

### Ver Tu Progreso
```
/progreso
```

Muestra:
- **Nivel actual**: Beginner, Intermediate, Advanced, Expert
- **XP total**: Puntos de experiencia acumulados
- **Progreso general**: Porcentaje de curriculum completado
- **Lecciones completadas**: Contador
- **Ejercicios entregados**: Total de entregas
- **Logros**: Badges desbloqueados
- **Puntuación media**: Promedio de tus calificaciones

### Sistema de Niveles
| Nivel | XP Requerido | Descripción |
|-------|--------------|-------------|
| Beginner | 0-199 | Aprendiendo fundamentos |
| Intermediate | 200-499 | Conocimientos sólidos |
| Advanced | 500-999 | Habilidades avanzadas |
| Expert | 1000+ | Dominio del campo |

### Logros Disponibles 🏆
- **Primera Lección**: Completa tu primera lección
- **Módulo A Completado**: Termina todos los fundamentos
- **10 Lecciones**: Completa 10 lecciones
- **Primer Ejercicio**: Entrega tu primer ejercicio
- **Experto OSINT**: Usa todas las herramientas OSINT

## 🎯 Especializaciones (Hats)

Disponibles después de completar 10 lecciones:

```
/especialidad
```

### ⚪ White Hat - Hacker Ético
- Enfoque en defensa
- Auditorías de seguridad
- Pentesting autorizado
- Compliance y normativas

### ⚫ Grey Hat - Investigador
- Bug bounty programs
- Investigación de vulnerabilidades
- Técnicas mixtas
- Divulgación responsable

### 🔵 Blue Hat - Defensor Corporativo
- SOC (Security Operations Center)
- SIEM y correlación
- Respuesta a incidentes
- Threat hunting

### 🔴 Red Hat - Operador Ofensivo
- Red team operations
- Simulación de adversarios
- Explotación avanzada
- Post-explotación

### 🔍 Forense Digital
- Análisis post-incidente
- Recuperación de evidencia
- Cadena de custodia
- Informes periciales

## 🛠️ Herramientas OSINT

### Análisis de Red
```
/ip 8.8.8.8
/domain google.com
/dns google.com
/ssl google.com
/subdomains google.com
```

### Análisis de Identidad
```
/email usuario@ejemplo.com
/phone +525551234567
/social juanperez
```

### Seguridad Web
```
/url https://ejemplo.com
/scanurl https://ejemplo.com
/image https://ejemplo.com/foto.jpg
```

### Contraseñas y Cifrado
```
/password MiContraseña123!
/genpass 16
/hash 5d41402abc4b2a76b9719d911017c592
/analyze SGVsbG8gV29ybGQ=
```

### Cifrado Educativo (Fernet/AES)
```
/encrypt MiClave HolaMundo
/decrypt MiClave gAAAAA...
```

## 📖 Recursos Adicionales

```
/recursos
```

Muestra:
- **Plataformas de práctica**: TryHackMe, HackTheBox, OverTheWire
- **Bug Bounty**: HackerOne, Bugcrowd, Intigriti
- **Aprendizaje**: OWASP, Portswigger Academy
- **Certificaciones**: CEH, OSCP, CompTIA Security+

## 💡 Consejos Útiles

### Para Aprender Mejor
1. **Sigue el orden**: Las lecciones están estructuradas progresivamente
2. **Practica**: Usa las herramientas OSINT para reforzar lo aprendido
3. **Toma notas**: Documenta conceptos importantes
4. **Repite**: Revisa lecciones si necesitas refrescar
5. **Experimenta**: Prueba comandos con ejemplos reales (autorizados)

### Para Ganar XP Rápido
- Completa todas las preguntas de comprensión (+10 XP cada una)
- Entrega ejercicios con buena calidad (hasta +50 XP)
- Completa lecciones completas (+50-120 XP)
- Desbloquea logros (bonus XP)

### Para Seguridad
- ⚠️ **Nunca practiques en sistemas sin autorización**
- ✅ Usa entornos de prueba (TryHackMe, HackTheBox)
- ✅ Lee y respeta las políticas de seguridad
- ✅ Reporta vulnerabilidades responsablemente

## 🔄 Comandos del Menú Interactivo

Usa botones en lugar de comandos:

### Menú Principal
```
/menu
```

Opciones:
- **🎓 Aprendizaje**: Lecciones, ejercicios, progreso
- **📊 Mi Progreso**: Estadísticas detalladas
- **🛰 OSINT básico**: IP, email, dominio, hash
- **🌐 Web / URL**: URLs, SSL, subdominios, DNS
- **🔐 Contraseñas / Cifrado**: Password, cifrado, generador
- **ℹ️ Herramientas info**: Historial, social, explicaciones
- **📚 Ayuda**: Guía rápida

## 🆘 Solución de Problemas

### No recibo XP
- Verifica que completaste la acción correctamente
- Usa `/progreso` para ver tu XP actual
- Las preguntas incorrectas no dan XP

### No puedo avanzar de lección
- Debes completar la lección actual con el botón **✅ Completar**
- Verifica que respondiste las preguntas
- Usa `/leccion` para ver tu lección actual

### El bot no responde
- Verifica tu conexión a internet
- Espera unos segundos y reintenta
- Usa `/start` para reiniciar

### Perdí mi progreso
- Tu progreso está guardado automáticamente en base de datos
- Usa `/start` para ver tu progreso actual
- Si hay un problema, contacta al administrador

## 📞 Comandos de Ayuda

```
/help          - Ayuda general
/menu          - Menú principal
/explain hash  - Explica concepto de hash
/explain ssl   - Explica SSL/TLS
/explain 2fa   - Explica autenticación de dos factores
/explain phishing - Explica ataques de phishing
```

## 🎓 Flujo de Aprendizaje Recomendado

### Semana 1: Fundamentos
1. Lecciones 1.1 - 1.5 (Módulo A)
2. Practica con herramientas OSINT básicas
3. Completa ejercicios de contraseñas

### Semana 2: Redes
1. Lecciones 2.1 - 2.2 (Módulo B)
2. Analiza tráfico de red
3. Usa comandos de DNS y subdominios

### Semana 3: Programación
1. Lecciones 3.1 - 3.2 (Módulo C)
2. Escribe scripts de seguridad
3. Practica prevención de SQL injection

### Semana 4: Pentesting
1. Lecciones 4.1 - 4.2 (Módulo D)
2. Realiza reconocimiento OSINT completo
3. Practica en plataformas como TryHackMe

### Semana 5+: Especialización
1. Elige tu Hat
2. Profundiza en tu especialización
3. Participa en bug bounty (si aplica)

---

**🎉 ¡Bienvenido a tu viaje en ciberseguridad!**

Recuerda: el aprendizaje es continuo. Mantente actualizado, practica constantemente y siempre actúa éticamente.

**⚠️ Disclaimer**: Todo el conocimiento debe usarse éticamente y legalmente.
