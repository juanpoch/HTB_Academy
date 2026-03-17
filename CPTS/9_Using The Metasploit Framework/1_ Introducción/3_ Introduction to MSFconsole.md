# Sección 2: Introducción a MSFconsole

## 🚀 Iniciando MSFconsole

Para comenzar a interactuar con Metasploit Framework, necesitamos escribir `msfconsole` en la terminal de nuestra elección.

### Distribuciones con MSFconsole Pre-instalado

Muchas distribuciones orientadas a seguridad vienen con `msfconsole` ya instalado:

- ✅ **Parrot Security OS**
- ✅ **Kali Linux**
- ✅ **BlackArch Linux**
- ✅ **BackBox**

### Flexibilidad de Línea de Comandos

Al igual que cualquier otra herramienta de línea de comandos, podemos usar varias opciones al lanzar el script:

- **Opciones gráficas**: Control de visualización
- **Opciones procedurales**: Automatización y scripting

---

## 🎨 Preparación: El Primer Contacto

### Lanzamiento Estándar de MSFconsole

Al ejecutar `msfconsole`, somos recibidos con:

1. **Arte ASCII (Splash Art)**: Banner artístico característico
2. **Prompt de comandos**: Esperando nuestro primer comando

```bash
CyberWolfSec@htb[/htb]$ msfconsole
```

**Salida típica**:
```
                                                  
                                              `:oDFo:`                            
                                           ./ymM0dayMmy/.                          
                                        -+dHJ5aGFyZGVyIQ==+-                    
                                    `:sm⏣~~Destroy.No.Data~~s:`                
                                 -+h2~~Maintain.No.Persistence~~h+-              
                             `:odNo2~~Above.All.Else.Do.No.Harm~~Ndo:`          
                          ./etc/shadow.0days-Data'%20OR%201=1--.No.0MN8'/.      
                       -++SecKCoin++e.AMd`       `.-://///+hbove.913.ElsMNh+-    
                      -~/.ssh/id_rsa.Des-                  `htN01UserWroteMe!-  
                      :dopeAW.No<nano>o                     :is:TЯiKC.sudo-.A:  
                      :we're.all.alike'`                     The.PFYroy.No.D7:  
                      :PLACEDRINKHERE!:                      yxp_cmdshell.Ab0:    
                      :msf>exploit -j.                       :Ns.BOB&ALICEes7:    
                      :---srwxrwx:-.`                        `MS146.52.No.Per:    
                      :<script>.Ac816/                        sENbove3101.404:    
                      :NT_AUTHORITY.Do                        `T:/shSYSTEM-.N:    
                      :09.14.2011.raid                       /STFU|wall.No.Pr:    
                      :hevnsntSurb025N.                      dNVRGOING2GIVUUP:    
                      :#OUTHOUSE-  -s:                       /corykennedyData:    
                      :$nmap -oS                              SSo.6178306Ence:    
                      :Awsm.da:                            /shMTl#beats3o.No.:    
                      :Ring0:                             `dDestRoyREXKC3ta/M:    
                      :23d:                               sSETEC.ASTRONOMYist:    
                       /-                        /yo-    .ence.N:(){ :|: & };:    
                                                 `:Shall.We.Play.A.Game?tron/    
                                                 ```-ooy.if1ghtf0r+ehUser5`    
                                               ..th3.H1V3.U2VjRFNN.jMh+.`          
                                              `MjM~~WE.ARE.se~~MMjMs              
                                               +~KANSAS.CITY's~-`                  
                                                J~HAKCERS~./.`                    
                                                .esc:wq!:`                        
                                                 +++ATH`                            
                                                  `


       =[ metasploit v6.1.9-dev                           ]
+ -- --=[ 2169 exploits - 1149 auxiliary - 398 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use sessions -1 to interact with the last opened session

msf6 >
```

### 🎯 Interpretando el Banner de Inicio

El banner nos muestra información crucial:

#### Estadísticas del Framework

```
=[ metasploit v6.1.9-dev                           ]
```
**Versión actual** de Metasploit Framework

```
+ -- --=[ 2169 exploits - 1149 auxiliary - 398 post       ]
```
- **2169 exploits**: Módulos de explotación disponibles
- **1149 auxiliary**: Módulos auxiliares (escáneres, fuzzers, etc.)
- **398 post**: Módulos de post-explotación

```
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
```
- **592 payloads**: Cargas útiles disponibles
- **45 encoders**: Codificadores para evasión
- **10 nops**: Generadores de NOP

```
+ -- --=[ 9 evasion                                       ]
```
- **9 evasion**: Módulos de evasión de seguridad

#### 💡 Tip del Día

```
Metasploit tip: Use sessions -1 to interact with the last opened session
```

Cada vez que iniciamos MSFconsole, recibimos un **tip útil** que nos ayuda a aprender nuevas funcionalidades.

### Lanzamiento Silencioso (Modo Quiet)

Si preferimos evitar el banner artístico, podemos usar la opción `-q` (quiet):

```bash
CyberWolfSec@htb[/htb]$ msfconsole -q

msf6 >
```

**Ventajas del modo quiet**:
- ✅ Inicio más rápido
- ✅ Ideal para scripts automatizados
- ✅ Menos ruido visual
- ✅ Útil en conexiones remotas lentas

---

## 📚 Explorando los Comandos Disponibles

### Comando de Ayuda

Para ver todos los comandos disponibles:

```bash
msf6 > help
```

Este comando despliega una lista completa de todas las funcionalidades disponibles en MSFconsole.

> 💡 **Recomendación**: Ejecuta `help` y explora cada categoría de comandos. La familiaridad con los comandos disponibles es fundamental para un uso eficiente de la herramienta.

---

## 🔧 Manteniendo Actualizado Metasploit Framework

### La Importancia de las Actualizaciones

> **"Nuestras herramientas deben estar afiladas"**

Una de las **primeras cosas** que debemos hacer es asegurarnos de que:
- Los módulos que componen el framework estén **actualizados**
- Los nuevos módulos disponibles públicamente puedan ser **importados**

### Método Antiguo vs. Método Actual

#### ❌ Método Antiguo (OBSOLETO)

```bash
# NO recomendado actualmente
msfupdate
```

Este comando solía ejecutarse en la terminal del sistema operativo (fuera de msfconsole) para actualizar el framework.

#### ✅ Método Actual (RECOMENDADO)

El **gestor de paquetes APT** ahora maneja las actualizaciones de módulos y características sin esfuerzo:

```bash
sudo apt update && sudo apt install metasploit-framework
```

### Proceso de Instalación/Actualización

**Comando completo**:
```bash
CyberWolfSec@htb[/htb]$ sudo apt update && sudo apt install metasploit-framework
```

**Salida típica**:
```
<SNIP>

(Reading database ... 414458 files and directories currently installed.)
Preparing to unpack .../metasploit-framework_6.0.2-0parrot1_amd64.deb ...
Unpacking metasploit-framework (6.0.2-0parrot1) over (5.0.88-0kali1) ...
Setting up metasploit-framework (6.0.2-0parrot1) ...
Processing triggers for man-db (2.9.1-1) ...
Scanning application launchers
Removing duplicate launchers from Debian
Launchers are updated
```

### ¿Qué se Actualiza?

- ✅ **Nuevos exploits** añadidos por la comunidad
- ✅ **Correcciones de bugs** en módulos existentes
- ✅ **Nuevos payloads** y técnicas de evasión
- ✅ **Mejoras de rendimiento** en el framework
- ✅ **Actualizaciones de seguridad** críticas

---

## 🔍 Antes de Explotar: El Proceso de Enumeración

### Paso Fundamental

Uno de los **primeros pasos** que cubriremos en este módulo es **buscar un exploit apropiado** para nuestro objetivo.

### ⚠️ Advertencia Importante

> **No podemos explotar lo que no conocemos**

Necesitamos tener una **perspectiva detallada del objetivo** antes de intentar cualquier explotación. Esto implica el proceso de **Enumeración**, que **precede** cualquier tipo de intento de explotación.

---

## 🎯 El Proceso de Enumeración Explicado

### ¿Qué es la Enumeración?

La **Enumeración** es el proceso de recopilar información detallada sobre el objetivo para identificar posibles vectores de ataque.

### Pasos Clave de la Enumeración

#### 1. **Identificar Servicios Públicamente Accesibles**

Durante la enumeración, debemos observar nuestro objetivo e identificar qué servicios de cara al público están ejecutándose en él.

**Preguntas fundamentales**:
- ¿Es un servidor HTTP? 
- ¿Es un servidor FTP?
- ¿Es una base de datos SQL?
- ¿Qué otros servicios están expuestos?

#### 2. **Determinar Versiones de Servicios**

> 🔑 **Las versiones son los componentes clave** durante el proceso de enumeración que nos permitirán determinar si el objetivo es vulnerable o no.

**Ejemplos de información a recopilar**:
```
Apache HTTP Server 2.4.29
OpenSSH 7.6p1
MySQL 5.7.33
ProFTPD 1.3.5
```

#### 3. **Escaneo Exhaustivo**

Necesitamos comenzar con un **escaneo exhaustivo** de la dirección IP del objetivo para determinar:
- ✅ **Qué servicio** está ejecutándose
- ✅ **Qué versión** está instalada para cada servicio
- ✅ **Configuraciones** expuestas
- ✅ **Puertos abiertos** y sus estados

### Tipos de Objetivos

Estas diferentes **tipologías de objetivos** varían sustancialmente en el mundo real:

| Tipo de Servicio | Ejemplo | Puerto Típico |
|------------------|---------|---------------|
| **Servidor Web** | Apache, Nginx, IIS | 80, 443 |
| **Servidor FTP** | ProFTPD, vsftpd | 21 |
| **Base de Datos** | MySQL, PostgreSQL, MSSQL | 3306, 5432, 1433 |
| **SSH** | OpenSSH | 22 |
| **SMB** | Samba, Windows File Sharing | 445, 139 |
| **Email** | Postfix, Exchange | 25, 110, 143 |

---

## 🚪 Identificando el Punto de Entrada

### Versiones Sin Parches

> **Las versiones sin parches de servicios previamente vulnerables** serán a menudo nuestro punto de entrada al sistema objetivo.

**Escenario típico**:
```
Servicio encontrado: Apache 2.4.29
Investigación: CVE-2019-0211 (Privilege Escalation)
Estado: VULNERABLE (sin parchar)
Acción: Buscar exploit en Metasploit
```

### Código Desactualizado

> **Código desactualizado en una plataforma accesible públicamente** será a menudo nuestro punto de entrada al sistema objetivo.

**Ejemplos comunes**:
- WordPress con plugins antiguos
- CMS (Drupal, Joomla) sin actualizar
- Paneles de administración con versiones antiguas
- Aplicaciones web custom sin mantenimiento

---

## 📊 Estructura de Compromiso de MSF

La estructura de compromiso de MSF puede dividirse en **cinco categorías principales**:

```
1. ENUMERACIÓN
   ↓
2. PREPARACIÓN
   ↓
3. EXPLOTACIÓN
   ↓
4. ESCALADA DE PRIVILEGIOS
   ↓
5. POST-EXPLOTACIÓN
```

### Beneficios de Esta Estructura

Esta división facilita:
- ✅ **Encontrar características** apropiadas de MSF de manera más estructurada
- ✅ **Seleccionar módulos** de forma organizada
- ✅ **Trabajar sistemáticamente** siguiendo una metodología clara
- ✅ **Documentar procesos** de manera ordenada

### Subcategorías Especializadas

Cada una de estas categorías tiene diferentes **subcategorías** destinadas a propósitos específicos:

- **Service Validation** (Validación de Servicios)
- **Vulnerability Research** (Investigación de Vulnerabilidades)
- **Code Auditing** (Auditoría de Código)
- **Module Execution** (Ejecución de Módulos)
- **Pivoting** (Pivoteo)
- **Data Exfiltration** (Exfiltración de Datos)

---

## 🗺️ Flowchart: Estructura Completa de Compromiso

A continuación, desglosamos cada fase de la estructura de compromiso:

### 📌 Fase 1: ENUMERACIÓN

```
ENUMERACIÓN
├── Service Validation (Validación de Servicios)
│   ├── Passive Scanning
│   │   ├── OSINT
│   │   ├── Interacting with services legitimately
│   │   └── whois / DNS records
│   └── Active Scanning
│       ├── nMap / Nessus / Nexpose scans
│       ├── Web server identification tools
│       └── Scan with identification tools
│
└── Vulnerability Research (Investigación de Vulnerabilidades)
    ├── ExploitDB (CVE)
    ├── Rapid7 (CVE)
    ├── SearchSploit (CLI)
    └── Google Dorking (CVE)
```

**Explicación detallada**:

#### Service Validation (Validación de Servicios)

**Passive Scanning (Escaneo Pasivo)**:
- **OSINT**: Recopilación de inteligencia de fuentes abiertas
- **Interacción legítima**: Interactuar con servicios de forma normal
- **whois/DNS**: Consultar registros públicos

**Active Scanning (Escaneo Activo)**:
- **nMap**: Escaneo de puertos y servicios
- **Nessus/Nexpose**: Escáneres de vulnerabilidades profesionales
- **Web identification tools**: Herramientas como WhatWeb, Wappalyzer

#### Vulnerability Research (Investigación de Vulnerabilidades)

**Bases de datos de exploits**:
- **ExploitDB**: Base de datos pública de exploits (CVE)
- **Rapid7**: Base de datos de Metasploit
- **SearchSploit**: Herramienta CLI para buscar en ExploitDB
- **Google Dorking**: Búsqueda avanzada de CVEs

### 📌 Fase 2: PREPARACIÓN

```
PREPARACIÓN
├── Code Auditing (Auditoría de Código)
│   └── Dependency Chains (Cadenas de Dependencias)
│
├── Reporting Custom Modules (Módulos Personalizados)
│
└── Required to Exploitation (Requerido para Explotación)
```

**Explicación detallada**:

#### Code Auditing (Auditoría de Código)
- Revisar el código del exploit antes de ejecutarlo
- Entender las **dependencias** necesarias
- Verificar que no haya comportamientos maliciosos

#### Reporting Custom Modules
- Crear módulos personalizados si es necesario
- Adaptar exploits públicos a nuestro entorno

#### Required to Exploitation
- Preparar el entorno de explotación
- Configurar listeners
- Preparar payloads

### 📌 Fase 3: EXPLOTACIÓN

```
EXPLOTACIÓN
├── Run Module Locally (Ejecutar Módulo Localmente)
│
├── Get Payloads? (¿Obtener Payloads?)
│   ├── Payloads shown selected
│   │   ├── REVERSE
│   │   ├── BIND/NETCAT
│   │   ├── LOADLIBRARY
│   │   ├── PASSIVESX
│   │   ├── IPKNOCKING
│   │   └── FIND_TAG
│   │
│   └── Targets shown selected
│       ├── METERPRETER
│       ├── Shell - CMD.shell.d
│       ├── ... (otros shells)
│       ├── VNC
│       ├── WINDOWS
│       ├── ENCODER
│       └── OTHERS
│
└── Next Target (Siguiente Objetivo)
```

**Explicación detallada**:

#### Run Module Locally (Ejecutar Módulo Localmente)
- Prueba del exploit antes del ataque real
- Verificación de funcionamiento

#### Get Payloads? (Selección de Payloads)

**Tipos de conexión (Payloads shown selected)**:

- **REVERSE**: Conexión inversa (el objetivo se conecta a nosotros)
  ```
  Objetivo → Atacante
  ```
  
- **BIND/NETCAT**: Conexión directa (nosotros nos conectamos al objetivo)
  ```
  Atacante → Objetivo
  ```
  
- **LOADLIBRARY**: Carga de bibliotecas dinámicas
- **PASSIVESX**: Conexiones pasivas
- **IPKNOCKING**: Port knocking antes de conexión
- **FIND_TAG**: Búsqueda de tags específicos

**Targets shown selected (Tipos de shell)**:

- **METERPRETER**: Shell avanzado de Metasploit
  - Post-explotación integrada
  - Evasión de antivirus
  - Funcionalidades extendidas

- **Shell - CMD.shell.d**: Shell estándar de comandos
  - Windows: cmd.exe
  - Linux: /bin/bash

- **VNC**: Acceso gráfico remoto
- **WINDOWS**: Payloads específicos de Windows
- **ENCODER**: Payloads codificados para evasión
- **OTHERS**: Otros tipos de payloads especializados

### 📌 Fase 4: ESCALADA DE PRIVILEGIOS

```
PRIVILEGE ESCALATION (ESCALADA DE PRIVILEGIOS)
├── Vulnerability Research (Investigación de Vulnerabilidades)
│   └── Already privileged to access
│       └── what privilege is needed
│
├── Credential Gathering (Recolección de Credenciales)
│
└── Token Impersonation (Suplantación de Tokens)
```

**Explicación detallada**:

#### Vulnerability Research
- Buscar vulnerabilidades de escalada de privilegios
- Identificar qué privilegios ya tenemos
- Determinar qué privilegios necesitamos

**Ejemplo**:
```
Usuario actual: www-data (bajos privilegios)
Objetivo: root (máximos privilegios)
Método: Exploit de kernel o SUID binaries
```

#### Credential Gathering (Recolección de Credenciales)
- Extraer contraseñas de archivos de configuración
- Dump de hashes de contraseñas
- Captura de credenciales en memoria
- Keylogging

**Herramientas comunes**:
- mimikatz (Windows)
- hashdump (Meterpreter)
- /etc/shadow (Linux)

#### Token Impersonation (Suplantación de Tokens)
- Robo de tokens de autenticación
- Impersonar usuarios con mayores privilegios
- Técnicas como Pass-the-Hash

### 📌 Fase 5: POST-EXPLOTACIÓN

```
POST-EXPLOITATION (POST-EXPLOTACIÓN)
├── Pivoting to Other Systems (Pivoteo a Otros Sistemas)
│   └── Use target to attack other machines
│
├── Credential Gathering (Recolección de Credenciales)
│   └── For lateral movement
│
├── Data Exfiltration (Exfiltración de Datos)
│   └── Extract valuable information
│
└── Cleanup (Limpieza)
    └── Remove traces of activity
```

**Explicación detallada**:

#### Pivoting to Other Systems (Pivoteo)
**Concepto**: Usar el sistema comprometido como **punto de apoyo** para atacar otros sistemas en la red interna.

**Escenario típico**:
```
Internet → [Sistema Web Comprometido] → Red Interna
                    ↓
            Base de Datos Interna
            Servidor de Archivos
            Controlador de Dominio
```

**Técnicas**:
- Port forwarding
- Proxy SOCKS
- VPN tunneling
- Route addition en Meterpreter

#### Credential Gathering (Recolección de Credenciales)

**Propósito**: Obtener credenciales para **movimiento lateral**

**Fuentes de credenciales**:
- Archivos de configuración
- Memoria del sistema
- Navegadores web
- Gestores de contraseñas
- Bases de datos locales

**Ejemplo**:
```bash
# En Meterpreter
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

#### Data Exfiltration (Exfiltración de Datos)

**Propósito**: Extraer información valiosa del sistema comprometido

**Tipos de datos objetivo**:
- 📄 Documentos confidenciales
- 🔑 Credenciales almacenadas
- 💾 Bases de datos
- 📧 Correos electrónicos
- 🔒 Claves privadas (SSH, SSL)
- 💰 Información financiera
- 👤 Datos personales (PII)

**Métodos de exfiltración**:
- Download directo vía Meterpreter
- Compresión y transferencia
- Tunelización por DNS
- Exfiltración por HTTPS

**Ejemplo**:
```bash
# En Meterpreter
meterpreter > download "C:\\Users\\Admin\\Documents\\passwords.txt" /root/loot/
```

#### Cleanup (Limpieza)

**Propósito**: Eliminar rastros de la actividad para mantener el acceso y evitar detección

**Acciones de limpieza**:
- 🗑️ Borrar logs de sistema
- 🔄 Restaurar archivos modificados
- ❌ Eliminar herramientas subidas
- 🕐 Ajustar timestamps
- 🧹 Limpiar historial de comandos

**Ejemplo**:
```bash
# En Meterpreter
meterpreter > clearev
[*] Clearing event logs...
```

---

## 🎓 Importancia de Familiarizarse con la Estructura

### ¿Por Qué es Crucial?

> Es **crucial** que nos familiaricemos con esta estructura.

**Razones**:

1. **Metodología clara**: Saber qué hacer en cada fase
2. **Eficiencia**: No perder tiempo buscando qué hacer
3. **Documentación**: Poder reportar nuestro proceso
4. **Reproducibilidad**: Otros pueden seguir nuestros pasos
5. **Profesionalismo**: Trabajar de manera organizada

### Recomendación de Aprendizaje

> Por lo tanto, examinaremos los componentes de este framework para comprender mejor cómo se relacionan entre sí.

**Proceso recomendado**:

1. **Revisar cada categoría** individualmente
2. **Profundizar en subcategorías** específicas
3. **Experimentar** con diferentes funciones
4. **Analizar resultados** independientemente
5. **Documentar aprendizajes** personales

---

## 🔬 La Importancia de la Experimentación

### Principio Fundamental

> **La experimentación con las diferentes funciones es una parte integral del aprendizaje** de una nueva herramienta o habilidad.

### Laboratorios Prácticos

> **Deberíamos probar todo lo imaginable** en los siguientes laboratorios y analizar los resultados independientemente.

**Sugerencias para experimentar**:

#### 1. **Probar Diferentes Módulos**
```bash
msf6 > search type:exploit platform:windows
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > info
```

#### 2. **Comparar Payloads**
```bash
msf6 > show payloads
# Probar diferentes payloads y observar comportamientos
```

#### 3. **Experimentar con Opciones**
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
msf6 exploit(windows/smb/ms17_010_eternalblue) > show advanced
msf6 exploit(windows/smb/ms17_010_eternalblue) > show evasion
```

#### 4. **Analizar Resultados**
- Documentar qué funciona y qué no
- Entender por qué ciertos exploits fallan
- Aprender de los errores

#### 5. **Crear Escenarios de Prueba**
- Configurar máquinas virtuales vulnerables
- Practicar en entornos controlados
- Validar técnicas antes de usarlas en producción

---

## 📝 Checklist de Preparación para MSFconsole

Antes de comenzar a trabajar con MSFconsole:

- [ ] Framework actualizado (`sudo apt update && sudo apt install metasploit-framework`)
- [ ] Comando `help` ejecutado y revisado
- [ ] Estructura de compromiso estudiada
- [ ] Entorno de laboratorio preparado
- [ ] Objetivo identificado para enumeración
- [ ] Documentación lista para tomar notas

---

## 🔑 Conceptos Clave para Recordar

1. **MSFconsole** es la interfaz principal de Metasploit
2. La **Enumeración** SIEMPRE precede a la Explotación
3. Las **versiones** de servicios son críticas para identificar vulnerabilidades
4. La **estructura de 5 fases** guía todo el proceso de compromiso
5. La **experimentación** es fundamental para el aprendizaje
6. Mantener el framework **actualizado** es esencial
7. Cada fase tiene **subcategorías especializadas**

---

## 🚀 Próximos Pasos

En las siguientes secciones, profundizaremos en:
- Comandos específicos de MSFconsole
- Búsqueda y selección de módulos
- Configuración de exploits
- Ejecución de ataques
- Gestión de sesiones de Meterpreter
- Técnicas de post-explotación

---

## 🎯 Ejercicio Práctico Sugerido

### Familiarización con MSFconsole

1. **Iniciar MSFconsole**:
```bash
msfconsole -q
```

2. **Explorar comandos básicos**:
```bash
msf6 > help
msf6 > version
msf6 > show -h
```

3. **Revisar estadísticas**:
```bash
msf6 > show exploits
msf6 > show payloads
msf6 > show auxiliary
```

4. **Buscar módulos**:
```bash
msf6 > search type:exploit platform:linux
msf6 > search cve:2021
```

5. **Experimentar con información**:
```bash
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > info
msf6 auxiliary(scanner/portscan/tcp) > show options
```

---

**¡La práctica constante con MSFconsole es la clave para dominar Metasploit!** 💪
