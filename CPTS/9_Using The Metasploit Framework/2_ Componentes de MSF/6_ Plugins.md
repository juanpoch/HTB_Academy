# Sección 8: Plugins en Metasploit

## 📋 Tabla de Contenidos

1. [¿Qué son los Plugins?](#qué-son-los-plugins)
2. [Ventajas de Usar Plugins](#ventajas-de-usar-plugins)
3. [Ubicación de Plugins](#ubicación-de-plugins)
4. [Usar Plugins Existentes](#usar-plugins-existentes)
5. [Instalar Nuevos Plugins](#instalar-nuevos-plugins)
6. [Plugins Populares](#plugins-populares)
7. [Mixins](#mixins)

---

## 🎯 ¿Qué son los Plugins?

### Definición

> Los **Plugins** son software disponible que ya ha sido lanzado por terceros y que han dado aprobación a los creadores de Metasploit para integrar su software dentro del framework.

### Tipos de Plugins

Los plugins pueden ser:

| Tipo | Descripción | Ejemplo |
|------|-------------|---------|
| **Productos Comerciales** | Software comercial con versión Community (gratuita con funcionalidad limitada) | Nessus, Nexpose |
| **Proyectos Individuales** | Desarrollados por personas individuales | DarkOperator's Plugins |
| **Integraciones de API** | Conectan con servicios externos | Mimikatz, OpenVAS |

---

## 🚀 Ventajas de Usar Plugins

### Antes de los Plugins

```
Workflow antiguo:
1. Nmap scan → Guardar XML
2. Importar a Metasploit
3. Nessus scan → Guardar resultados
4. Importar a Metasploit
5. Configurar opciones manualmente
6. Exportar resultados
7. Importar a otra herramienta
... (repetir ciclo)
```

**Problemas**:
- ❌ Muchas herramientas separadas
- ❌ Importar/Exportar constantemente
- ❌ Configurar parámetros repetidamente
- ❌ Datos no sincronizados

---

### Con Plugins

```
Workflow moderno:
1. Cargar plugin en msfconsole
2. Ejecutar scans directamente
3. Resultados automáticamente en database
4. Hosts, services, vulnerabilidades disponibles
5. Todo sincronizado y documentado
```

**Beneficios**:
- ✅ Todo dentro de msfconsole
- ✅ Documentación automática en database
- ✅ Hosts, servicios y vulnerabilidades visibles de inmediato
- ✅ Sin importar/exportar manual
- ✅ Configuración centralizada

---

## 📁 Ubicación de Plugins

### Directorio por Defecto

```bash
/usr/share/metasploit-framework/plugins
```

Este es el directorio predeterminado para cada instalación nueva de msfconsole.

### Ver Plugins Disponibles

```bash
$ ls /usr/share/metasploit-framework/plugins

aggregator.rb      beholder.rb        event_tester.rb  komand.rb     msfd.rb    nexpose.rb   request.rb  session_notifier.rb  sounds.rb  token_adduser.rb  wmap.rb
alias.rb           db_credcollect.rb  ffautoregen.rb   lab.rb        msgrpc.rb  openvas.rb   rssfeed.rb  session_tagger.rb    sqlmap.rb  token_hunter.rb
auto_add_route.rb  db_tracker.rb      ips_filter.rb    libnotify.rb  nessus.rb  pcap_log.rb  sample.rb   socket_logger.rb     thread.rb  wiki.rb
```

**Formato**: Todos los plugins son archivos `.rb` (Ruby)

---

## 🔧 Usar Plugins Existentes

### Paso 1: Cargar Plugin

Usamos el comando `load` seguido del nombre del plugin:

```bash
msf6 > load nessus

[*] Nessus Bridge for Metasploit
[*] Type nessus_help for a command listing
[*] Successfully loaded Plugin: Nessus
```

**Indicadores de éxito**:
- ✅ Mensaje de bienvenida del plugin
- ✅ Instrucciones de ayuda
- ✅ "Successfully loaded Plugin"

---

### Paso 2: Ver Comandos Disponibles

Cada plugin tiene su propio menú de ayuda:

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
nessus_policy_list          List all polciies
nessus_policy_del           Delete a policy
```

**Observación**: El menú de ayuda se extiende automáticamente con los comandos del plugin.

---

### Error: Plugin No Encontrado

Si el plugin no está instalado correctamente:

```bash
msf6 > load Plugin_That_Does_Not_Exist

[-] Failed to load plugin from /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist.rb: cannot load such file -- /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist.rb
```

**Causas comunes**:
- ❌ Plugin no está en el directorio correcto
- ❌ Nombre del plugin incorrecto
- ❌ Plugin no tiene permisos correctos
- ❌ Plugin no está instalado

---

## 📥 Instalar Nuevos Plugins

### Método Automático: Actualizaciones del Sistema

Los plugins populares se instalan automáticamente con cada actualización del sistema operativo (Parrot OS, Kali Linux).

```bash
# Actualizar sistema (incluye nuevos plugins)
$ sudo apt update
$ sudo apt upgrade
```

**Beneficio**: Plugins automáticamente en `/usr/share/metasploit-framework/plugins`

---

### Método Manual: Plugins Personalizados

Para instalar plugins personalizados **no incluidos** en actualizaciones del sistema:

#### Paso 1: Descargar el Plugin

Ejemplo con **DarkOperator's Metasploit-Plugins**:

```bash
$ git clone https://github.com/darkoperator/Metasploit-Plugins

Cloning into 'Metasploit-Plugins'...
remote: Enumerating objects: 184, done.
remote: Total 184 (delta 0), reused 0 (delta 0), pack-reused 184
Receiving objects: 100% (184/184), 50.52 KiB | 2.11 MiB/s, done.
Resolving deltas: 100% (82/82), done.
```

---

#### Paso 2: Ver Plugins Descargados

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

**Observación**: Repositorio contiene múltiples plugins en formato `.rb`

---

#### Paso 3: Copiar Plugin al Directorio de MSF

Ejemplo con el plugin `pentest.rb`:

```bash
$ sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```

**Importante**:
- ✅ Usar `sudo` para permisos de escritura
- ✅ Copiar a `/usr/share/metasploit-framework/plugins/`
- ✅ Mantener extensión `.rb`

---

#### Paso 4: Verificar Instalación

Iniciar msfconsole y cargar el plugin:

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

**Indicadores de éxito**:
- ✅ Banner ASCII del plugin
- ✅ Versión del plugin
- ✅ Autor del plugin
- ✅ "Successfully loaded plugin"

---

### Comandos Agregados por el Plugin

Después de cargar el plugin, el menú de ayuda se extiende:

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

**Categorías de comandos agregados**:
1. **Tradecraft Commands** - Técnicas operacionales
2. **auto_exploit Commands** - Explotación automatizada
3. **Discovery Commands** - Descubrimiento de redes
4. **Project Commands** - Gestión de proyectos
5. **Postauto Commands** - Post-explotación automatizada

---

## 🌟 Plugins Populares

### Plugins Pre-instalados

| Plugin | Descripción | Pre-instalado |
|--------|-------------|---------------|
| **nMap** | Integración con Nmap para scanning | ✅ Sí |
| **NexPose** | Integración con Rapid7 Nexpose | ✅ Sí |
| **Nessus** | Integración con Tenable Nessus | ✅ Sí |
| **Mimikatz** | Extracción de credenciales Windows (v1) | ✅ Sí |
| **Stdapi** | API estándar de Meterpreter | ✅ Sí |
| **Incognito** | Suplantación de tokens | ✅ Sí |

---

### Plugins de Terceros

| Plugin | Descripción | Pre-instalado |
|--------|-------------|---------------|
| **Railgun** | Llamadas a Windows API desde Meterpreter | ❌ No |
| **Priv** | Escalada de privilegios | ❌ No |
| **DarkOperator's** | Suite de automatización de pentesting | ❌ No |

---

### Descripción de Plugins Principales

#### 1. Nmap Plugin

**Función**: Ejecutar scans de Nmap directamente desde msfconsole

**Ventajas**:
- ✅ Resultados automáticamente en database
- ✅ No necesitas salir de msfconsole
- ✅ Integración con workflows de Metasploit

**Uso básico**:
```bash
msf6 > load nmap
msf6 > nmap -sV -sC 10.10.10.0/24
```

---

#### 2. Nessus Plugin

**Función**: Integración con Tenable Nessus vulnerability scanner

**Capacidades**:
- Conectar a servidor Nessus
- Ejecutar scans de vulnerabilidades
- Importar resultados automáticamente
- Gestionar políticas de scan

**Workflow**:
```bash
msf6 > load nessus
msf6 > nessus_connect admin:password@localhost:8834
msf6 > nessus_scan_new <policy_id> scan1 10.10.10.0/24
msf6 > nessus_scan_status
msf6 > nessus_report_vulns <scan_id>
```

---

#### 3. Nexpose Plugin

**Función**: Integración con Rapid7 Nexpose (ahora InsightVM)

**Características**:
- Gestión de sites y assets
- Ejecución de scans
- Importación de vulnerabilidades
- Reporting integrado

**Uso**:
```bash
msf6 > load nexpose
msf6 > nexpose_connect admin:password@localhost:3780
msf6 > nexpose_scan <site_name>
```

---

#### 4. Mimikatz Plugin

**Función**: Extracción de credenciales de Windows

**Capacidades**:
- Dump de passwords en memoria
- Extracción de tickets Kerberos
- Pass-the-Hash
- Pass-the-Ticket

**Nota**: ⚠️ Versión 1 pre-instalada puede estar desactualizada

**Uso desde Meterpreter**:
```bash
meterpreter > load mimikatz
meterpreter > mimikatz_command -f sekurlsa::logonpasswords
```

---

#### 5. Railgun Plugin

**Función**: Permite hacer llamadas directas a la Windows API desde Meterpreter

**Ventajas**:
- ✅ Acceso a funciones nativas de Windows
- ✅ No necesita subir archivos
- ✅ Operación en memoria
- ✅ Evasión de AV

**Uso**:
```bash
meterpreter > irb
>> client.railgun.netapi32.NetUserAdd(...)
```

---

#### 6. Incognito Plugin

**Función**: Suplantación y robo de tokens de Windows

**Capacidades**:
- Listar tokens disponibles
- Suplantar tokens de usuario
- Delegar tokens
- Escalada de privilegios lateral

**Uso**:
```bash
meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "NT AUTHORITY\SYSTEM"
```

---

#### 7. DarkOperator's Plugins Suite

**Función**: Colección de plugins para automatización de pentesting

**Plugins incluidos**:
- **pentest.rb** - Automatización de workflows
- **auto_exploit** - Explotación automatizada
- **network_discover** - Descubrimiento de redes
- **pivot_network_discover** - Pivoting automatizado

**Características**:
- ✅ Multi-session management
- ✅ Credential harvesting automatizado
- ✅ Post-explotación masiva
- ✅ Gestión de proyectos

**Instalación**:
```bash
git clone https://github.com/darkoperator/Metasploit-Plugins
sudo cp Metasploit-Plugins/*.rb /usr/share/metasploit-framework/plugins/
```

---

## 🧩 Mixins

### ¿Qué son los Mixins?

> **Mixins** son clases que actúan como métodos para uso de otras clases **sin tener que ser la clase padre** de esas otras clases.

**Concepto clave**: No es herencia, es **inclusión**.

### Analogía Simple

```
Herencia (Tradicional):
Animal (clase padre)
  └── Perro (clase hija)
      └── Perro hereda TODO de Animal

Mixin (Modular):
Nadar (mixin)
Volar (mixin)
Caminar (mixin)

Pato = Animal + Nadar + Volar + Caminar
Pez = Animal + Nadar
Pájaro = Animal + Volar + Caminar
```

**Ventaja**: Puedes "mezclar" funcionalidades según necesites, sin cadenas de herencia complejas.

---

### ¿Por Qué Usar Mixins?

**Se usan principalmente cuando**:

1. **Queremos proveer muchas características opcionales para una clase**
   - Ejemplo: Meterpreter puede tener o no capacidad de keylogging
   
2. **Queremos usar una característica particular para múltiples clases**
   - Ejemplo: Módulo de scanning puede usarse en exploits, auxiliary, post

---

### Mixins en Ruby y Metasploit

**Lenguaje**: Metasploit Framework está escrito en **Ruby**, un lenguaje orientado a objetos.

**Implementación**: En Ruby, los Mixins se implementan usando la palabra **`include`**

```ruby
# Ejemplo simplificado
module HTTPClient
  def http_get(url)
    # Código para hacer HTTP GET
  end
end

module FTPClient
  def ftp_connect(host)
    # Código para conectar a FTP
  end
end

class ExploitModule
  include HTTPClient  # Ahora tiene http_get
  include FTPClient   # Ahora tiene ftp_connect
end
```

---

### Impacto en Metasploit

**La mayoría del lenguaje Ruby gira alrededor de Mixins como Módulos.**

**Ejemplos en Metasploit**:

| Mixin | Funcionalidad |
|-------|---------------|
| **Exploit::Remote::Tcp** | Conexiones TCP |
| **Exploit::Remote::HttpClient** | Requests HTTP |
| **Auxiliary::Scanner** | Capacidad de scanning |
| **Post::Windows::WLAN** | Extracción de passwords WiFi |
| **Payload::Windows::ReflectiveDLLInject** | Inyección de DLL |

**Ventaja**: Código modular y reutilizable.

---

### Recursos para Aprender Más sobre Mixins

**Documentación**:
- Ruby Mixins Tutorial: https://www.tutorialspoint.com/ruby/ruby_modules.htm
- Metasploit Development Guide: https://docs.metasploit.com

**Lectura adicional**:
- "Understanding Ruby Mixins" - https://www.sitepoint.com/understanding-ruby-mixins/

---

## ⚠️ Nota para Principiantes

### ¿Necesito Entender Mixins para Usar Metasploit?

**Respuesta corta**: ❌ **NO**

> Si estás comenzando con Metasploit, **no deberías preocuparte** por el uso de Mixins o su impacto en tu evaluación.

**¿Por qué se mencionan?**

Los Mixins se mencionan aquí como una **nota** de:
- ✅ Qué tan compleja puede volverse la personalización de Metasploit
- ✅ Cómo está estructurado el código internamente
- ✅ Por qué Metasploit es tan flexible y extensible

**Cuándo importan los Mixins**:
- ✅ Al **desarrollar tus propios módulos**
- ✅ Al **personalizar exploits existentes**
- ✅ Al **crear plugins personalizados**
- ✅ Al **contribuir al framework**

**Para uso básico/intermedio**: Enfócate en usar los plugins y módulos existentes.

---

## 💡 Mejores Prácticas

### 1. Explorar Plugins Disponibles

```bash
# Ver todos los plugins instalados
$ ls /usr/share/metasploit-framework/plugins

# Cargar y explorar cada uno
msf6 > load <plugin_name>
msf6 > help  # Ver comandos agregados
```

---

### 2. Mantener Plugins Actualizados

```bash
# Actualizar sistema regularmente
$ sudo apt update && sudo apt upgrade

# Verificar versiones de plugins
msf6 > load plugin_name
# Ver mensaje de versión
```

---

### 3. Documentar Plugins Personalizados

Cuando instales plugins de terceros:

```bash
# Crear archivo de documentación
$ cat > /usr/share/metasploit-framework/plugins/README_custom.md << EOF
## Custom Plugins Installed

- pentest.rb (DarkOperator) - v1.6 - Instalado: 2024-03-20
  Fuente: https://github.com/darkoperator/Metasploit-Plugins
  
- otro_plugin.rb - v2.1 - Instalado: 2024-03-21
  Fuente: ...
EOF
```

---

### 4. Probar Plugins en Entorno de Pruebas

**NUNCA** cargues plugins desconocidos directamente en operaciones reales:

```bash
# 1. Crear workspace de pruebas
msf6 > workspace -a TEST_PLUGINS

# 2. Cargar plugin
msf6 > load nuevo_plugin

# 3. Probar comandos
msf6 > nuevo_plugin_help
msf6 > nuevo_plugin_test_command

# 4. Verificar que no rompe nada
msf6 > search ms17_010
msf6 > use exploit/windows/smb/ms17_010_eternalblue
```

**Solo después de verificar** → Usar en operaciones reales

---

### 5. Permisos Correctos

```bash
# Verificar permisos del plugin
$ ls -la /usr/share/metasploit-framework/plugins/pentest.rb
-rw-r--r-- 1 root root 15234 Mar 20 10:30 pentest.rb

# Debe ser legible por tu usuario
# Si no funciona, verificar permisos:
$ sudo chmod 644 /usr/share/metasploit-framework/plugins/pentest.rb
```

---

## 🔑 Comandos de Referencia Rápida

### Gestión de Plugins

```bash
# Ver plugins disponibles (desde terminal)
ls /usr/share/metasploit-framework/plugins

# Cargar plugin (desde msfconsole)
msf6 > load <plugin_name>

# Ver ayuda del plugin
msf6 > <plugin_name>_help

# Ver comandos agregados
msf6 > help

# Descargar plugins de terceros
git clone https://github.com/darkoperator/Metasploit-Plugins

# Instalar plugin manualmente
sudo cp plugin.rb /usr/share/metasploit-framework/plugins/
```

---

## 📊 Tabla Comparativa: Plugins vs Módulos

| Característica | Plugins | Módulos |
|----------------|---------|---------|
| **Propósito** | Extender funcionalidad de msfconsole | Realizar acciones específicas (exploit, scan, etc.) |
| **Ubicación** | `/usr/share/metasploit-framework/plugins/` | `/usr/share/metasploit-framework/modules/` |
| **Formato** | Archivos `.rb` | Archivos `.rb` en estructura de carpetas |
| **Carga** | `load <plugin>` | `use <module>` |
| **Persistencia** | Se carga una vez por sesión | Se usa cuando se necesita |
| **Integración** | API completa del framework | API limitada al tipo de módulo |
| **Ejemplos** | Nessus, Nmap, Pentest | ms17_010, auxiliary/scanner/portscan |

---

## 🎯 Workflow Ejemplo con Plugins

### Scenario: Pentest Completo con Plugins

```bash
# 1. Crear workspace
msf6 > workspace -a Cliente_ABC

# 2. Cargar plugin de scanning
msf6 > load nessus
msf6 > nessus_connect admin:password@localhost:8834

# 3. Ejecutar scan de vulnerabilidades
msf6 > nessus_scan_new 1 "Cliente_ABC_Scan" 192.168.1.0/24
msf6 > nessus_scan_status

# 4. Importar resultados
msf6 > nessus_report_list
msf6 > nessus_report_vulns <scan_id>

# 5. Ver vulnerabilidades en database
msf6 > vulns

# 6. Cargar plugin de automatización
msf6 > load pentest

# 7. Ejecutar auto-explotación
msf6 > vuln_exploit

# 8. Post-explotación masiva
msf6 > sys_creds
msf6 > app_creds

# 9. Exportar resultados
msf6 > db_export -f xml cliente_abc_results.xml
```

---

## 🎓 Resumen Ejecutivo

### Conceptos Clave

1. **Plugins** = Software de terceros integrado en Metasploit
2. **Ubicación** = `/usr/share/metasploit-framework/plugins/`
3. **Formato** = Archivos `.rb` (Ruby)
4. **Carga** = `load <plugin_name>`
5. **Ventaja principal** = Integración sin salir de msfconsole

### Lo Que Aprendimos

✅ **Qué son** los plugins y por qué usarlos  
✅ **Dónde se ubican** los plugins en el sistema  
✅ **Cómo cargar** plugins existentes  
✅ **Cómo instalar** plugins personalizados  
✅ **Plugins populares** (Nessus, Nmap, Mimikatz, etc.)  
✅ **Mixins** (conceptualmente, para desarrollo futuro)  

### Plugins Más Útiles

**Para pentesting diario**:
1. **Nmap** - Scanning integrado
2. **Nessus/Nexpose** - Vulnerability scanning
3. **DarkOperator's Pentest** - Automatización
4. **Incognito** - Token impersonation
5. **Mimikatz** - Credential dumping

### Cuándo Usar Plugins

✅ **Cuando necesitas** integración con herramientas externas  
✅ **Cuando quieres** automatizar tareas repetitivas  
✅ **Cuando buscas** mantener todo en un solo lugar  
✅ **Cuando trabajas** en proyectos grandes con muchos hosts  

---

## 📚 Recursos Adicionales

### Documentación Oficial
- https://docs.metasploit.com/docs/using-metasploit/intermediate/using-plugins.html
- https://github.com/rapid7/metasploit-framework/wiki/Plugins

### Repositorios de Plugins
- **DarkOperator's Metasploit-Plugins**: https://github.com/darkoperator/Metasploit-Plugins
- **Community Plugins**: https://github.com/rapid7/metasploit-framework/tree/master/plugins

### Desarrollo de Plugins
- **Creating Metasploit Plugins**: https://docs.metasploit.com/docs/development/developing-modules/
- **Ruby Mixins Tutorial**: https://www.tutorialspoint.com/ruby/ruby_modules.htm

---

**¡Los plugins hacen de Metasploit una plataforma aún más poderosa y flexible!** 🚀
