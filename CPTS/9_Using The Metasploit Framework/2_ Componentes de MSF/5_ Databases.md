# Sección 7: Databases en Metasploit

## 📋 Tabla de Contenidos

1. [¿Qué son las Databases en msfconsole?](#qué-son-las-databases-en-msfconsole)
2. [Configurar la Base de Datos PostgreSQL](#configurar-la-base-de-datos-postgresql)
3. [Inicializar MSF Database](#inicializar-msf-database)
4. [Solución de Problemas](#solución-de-problemas)
5. [Comandos de Database](#comandos-de-database)
6. [Workspaces](#workspaces)
7. [Importar Resultados de Scans](#importar-resultados-de-scans)
8. [Usar Nmap dentro de MSFconsole](#usar-nmap-dentro-de-msfconsole)
9. [Backup de Datos](#backup-de-datos)
10. [Gestión de Hosts](#gestión-de-hosts)
11. [Gestión de Services](#gestión-de-services)
12. [Gestión de Credentials](#gestión-de-credentials)
13. [Gestión de Loot](#gestión-de-loot)

---

## 🎯 ¿Qué son las Databases en msfconsole?

### Problema que Resuelven

> Durante evaluaciones de máquinas complejas, y mucho más en redes enteras, las cosas pueden volverse un poco confusas y complicadas debido a la **gran cantidad** de:
> - Resultados de búsqueda
> - Puntos de entrada
> - Problemas detectados
> - Credenciales descubiertas
> - Servicios vulnerables
> - Hosts comprometidos

### Solución: Databases

**Las Databases** en msfconsole permiten:
- ✅ **Rastrear** todos los resultados de forma organizada
- ✅ **Acceso directo** y rápido a resultados de scans
- ✅ **Importar/Exportar** datos con herramientas de terceros
- ✅ **Configurar módulos** automáticamente con hallazgos existentes
- ✅ **Persistencia** de información entre sesiones

---

## 🗄️ Sistema de Base de Datos: PostgreSQL

### ¿Por Qué PostgreSQL?

Msfconsole tiene **soporte integrado** para el sistema de base de datos **PostgreSQL**.

**Ventajas**:
- 🔥 Robusto y confiable
- 🔥 Rendimiento excelente
- 🔥 Open source
- 🔥 Ampliamente soportado
- 🔥 Integración nativa con Metasploit

---

## 🚀 Configurar la Base de Datos PostgreSQL

### Paso 1: Verificar Estado de PostgreSQL

Primero, asegurémonos de que el servidor PostgreSQL esté corriendo:

```bash
$ sudo service postgresql status

● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: active (exited) since Fri 2022-05-06 14:51:30 BST; 3min 51s ago
    Process: 2147 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 2147 (code=exited, status=0/SUCCESS)
        CPU: 1ms

May 06 14:51:30 pwnbox-base systemd[1]: Starting PostgreSQL RDBMS...
May 06 14:51:30 pwnbox-base systemd[1]: Finished PostgreSQL RDBMS.
```

**Estado**: `Active: active (exited)` = ✅ Corriendo

---

### Paso 2: Iniciar PostgreSQL (si no está corriendo)

```bash
$ sudo systemctl start postgresql
```

**Sin output** = Comando ejecutado correctamente.

---

## 🔧 Inicializar MSF Database

### Comando: msfdb init

Después de iniciar PostgreSQL, necesitamos crear e inicializar la base de datos MSF:

```bash
$ sudo msfdb init

[i] Database already started
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```

**Lo que hace este comando**:
1. ✅ Crea usuario de database `msf`
2. ✅ Crea databases `msf` y `msf_test`
3. ✅ Crea archivo de configuración `database.yml`
4. ✅ Crea esquema inicial de la base de datos

---

## ⚠️ Solución de Problemas

### Error Común: NoMethodError

A veces puede ocurrir un error si Metasploit **no está actualizado**:

```bash
$ sudo msfdb init

[i] Database already started
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
rake aborted!
NoMethodError: undefined method `without' for #<Bundler::Settings:0x000055dddcf8cba8>
Did you mean? with_options
```

### Solución: Actualizar Metasploit

```bash
# 1. Actualizar Metasploit
$ sudo apt update
$ sudo apt upgrade metasploit-framework

# 2. Reintentar inicialización
$ sudo msfdb init

[i] Database already started
[i] The database appears to be already configured, skipping initialization
```

**Mensaje**: "database appears to be already configured" = ✅ Ya está configurada

---

### Verificar Estado de la Database

```bash
$ sudo msfdb status

● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: active (exited) since Mon 2022-05-09 15:19:57 BST; 35min ago
    Process: 2476 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 2476 (code=exited, status=0/SUCCESS)
        CPU: 1ms

May 09 15:19:57 pwnbox-base systemd[1]: Starting PostgreSQL RDBMS...
May 09 15:19:57 pwnbox-base systemd[1]: Finished PostgreSQL RDBMS.

COMMAND   PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
postgres 2458 postgres    5u  IPv6  34336      0t0  TCP localhost:5432 (LISTEN)
postgres 2458 postgres    6u  IPv4  34337      0t0  TCP localhost:5432 (LISTEN)

UID          PID    PPID  C STIME TTY      STAT   TIME CMD
postgres    2458       1  0 15:19 ?        Ss     0:00 /usr/lib/postgresql/13/bin/postgres -D /var/lib/postgresql/13/main -c con

[+] Detected configuration file (/usr/share/metasploit-framework/config/database.yml)
```

**Detalles importantes**:
- PostgreSQL escuchando en puerto **5432** (IPv4 e IPv6)
- Proceso corriendo como usuario `postgres`
- Archivo de configuración detectado ✅

---

### Inicialización Exitosa (Fresh Install)

Si es una instalación fresca (sin errores previos):

```bash
$ sudo msfdb init

[+] Starting database
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```

**Todo correcto** = Listo para usar

---

## 🔌 Conectar a la Database

### Comando: msfdb run

Después de inicializar la database, iniciamos msfconsole **conectado a la database**:

```bash
$ sudo msfdb run

[i] Database already started
                                                  
         .                                         .
 .

      dBBBBBBb  dBBBP dBBBBBBP dBBBBBb  .                       o
       '   dB'                     BBP
    dB'dB'dB' dBBP     dBP     dBP BB
   dB'dB'dB' dBP      dBP     dBP  BB
  dB'dB'dB' dBBBBP   dBP     dBBBBBBB

                                   dBBBBBP  dBBBBBb  dBP    dBBBBP dBP dBBBBBBP
          .                  .                  dB' dBP    dB'.BP
                             |       dBP    dBBBB' dBP    dB'.BP dBP    dBP
                           --o--    dBP    dBP    dBP    dB'.BP dBP    dBP
                             |     dBBBBP dBP    dBBBBP dBBBBBP dBP    dBP

                                                                    .
                .
        o                  To boldly go where no
                            shell has gone before


       =[ metasploit v6.1.39-dev                          ]
+ -- --=[ 2214 exploits - 1171 auxiliary - 396 post       ]
+ -- --=[ 616 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

msf6>
```

**Observación**: msfconsole inicia **directamente conectado** a la database.

---

### Reinicializar Database (Si hay problemas de password)

Si ya tienes la database configurada pero **no puedes cambiar la contraseña** del usuario MSF:

```bash
# 1. Reinicializar database
$ msfdb reinit

# 2. Copiar archivo de configuración
$ cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/

# 3. Reiniciar PostgreSQL
$ sudo service postgresql restart

# 4. Iniciar msfconsole
$ msfconsole -q

msf6 > db_status

[*] Connected to msf. Connection type: PostgreSQL.
```

**Resultado**: Database reconectada ✅

---

## 📖 Comandos de Database

### Help Database

Msfconsole ofrece ayuda integrada para la database:

```bash
msf6 > help database

Database Backend Commands
=========================

    Command           Description
    -------           -----------
    db_connect        Connect to an existing database
    db_disconnect     Disconnect from the current database instance
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache
    db_status         Show the current database status
    hosts             List all hosts in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces
```

---

### Tabla de Comandos Principales

| Comando | Descripción |
|---------|-------------|
| **db_connect** | Conectar a una database existente |
| **db_disconnect** | Desconectar de la database actual |
| **db_export** | Exportar contenido de la database a archivo |
| **db_import** | Importar resultados de scan (auto-detecta tipo) |
| **db_nmap** | Ejecutar nmap y guardar resultados automáticamente |
| **db_rebuild_cache** | Reconstruir caché de módulos |
| **db_status** | Mostrar estado de conexión |
| **hosts** | Listar todos los hosts en la database |
| **loot** | Listar todo el loot en la database |
| **notes** | Listar todas las notas |
| **services** | Listar todos los servicios |
| **vulns** | Listar todas las vulnerabilidades |
| **workspace** | Cambiar entre workspaces |

---

### Verificar Conexión: db_status

```bash
msf6 > db_status

[*] Connected to msf. Connection type: postgresql.
```

**Estado**: `Connected to msf` = ✅ Conectado correctamente

---

## 📁 Workspaces

### ¿Qué son los Workspaces?

> Podemos pensar en **Workspaces** de la misma manera que pensamos en **carpetas de un proyecto**. Podemos segregar diferentes resultados de scans, hosts, e información extraída por IP, subred, red, o dominio.

**Analogía**:
```
Workspaces = Carpetas de proyecto

Proyecto_Cliente_A/
├── Resultados_Scan_1
├── Hosts_Comprometidos
└── Credenciales_Encontradas

Proyecto_Cliente_B/
├── Resultados_Scan_1
└── Vulnerabilidades
```

---

### Ver Workspaces Actuales

```bash
msf6 > workspace

* default
```

**Observación**: 
- `*` = Workspace actualmente en uso
- `default` = Workspace por defecto

---

### Crear Nuevo Workspace

```bash
msf6 > workspace -a Target_1

[*] Added workspace: Target_1
[*] Workspace: Target_1

msf6 > workspace

  default
* Target_1
```

**Parámetros**:
- `-a [name]` = Agregar nuevo workspace

**Resultado**: Target_1 ahora es el workspace activo (*)

---

### Cambiar de Workspace

```bash
msf6 > workspace Target_1

[*] Workspace: Target_1
```

**Sintaxis**: `workspace [name]`

---

### Ayuda de Workspaces

```bash
msf6 > workspace -h

Usage:
    workspace                  List workspaces
    workspace -v               List workspaces verbosely
    workspace [name]           Switch workspace
    workspace -a [name] ...    Add workspace(s)
    workspace -d [name] ...    Delete workspace(s)
    workspace -D               Delete all workspaces
    workspace -r <old> <new>   Rename workspace
    workspace -h               Show this help information
```

---

### Tabla de Opciones de Workspace

| Opción | Descripción |
|--------|-------------|
| `workspace` | Listar todos los workspaces |
| `workspace -v` | Listar workspaces con detalles |
| `workspace [name]` | Cambiar a workspace específico |
| `workspace -a [name]` | Agregar nuevo workspace |
| `workspace -d [name]` | Eliminar workspace |
| `workspace -D` | Eliminar TODOS los workspaces |
| `workspace -r <old> <new>` | Renombrar workspace |
| `workspace -h` | Mostrar ayuda |

---

## 📥 Importar Resultados de Scans

### Archivo Nmap de Ejemplo

Supongamos que tenemos un scan de Nmap guardado:

```bash
$ cat Target.nmap

Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-17 20:54 UTC
Nmap scan report for 10.10.10.40
Host is up (0.017s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.81 seconds
```

**Información importante**:
- Host: **10.10.10.40**
- OS: **Windows 7 - 10**
- Hostname: **HARIS-PC**
- Puertos abiertos: **9** (RPC y SMB)

---

### Importar con db_import

⚠️ **Importante**: El formato preferido para `db_import` es **.xml**

```bash
msf6 > db_import Target.xml

[*] Importing 'Nmap XML' data
[*] Import: Parsing with 'Nokogiri v1.10.9'
[*] Importing host 10.10.10.40
[*] Successfully imported ~/Target.xml
```

**Proceso**:
1. Detecta tipo de archivo (Nmap XML)
2. Parsea con Nokogiri
3. Importa host
4. Éxito ✅

---

### Verificar Hosts Importados

```bash
msf6 > hosts

Hosts
=====

address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------  ---------  -----  -------  ----  --------
10.10.10.40             Unknown                    device         
```

**Columnas**:
- **address**: IP del host
- **mac**: Dirección MAC (vacía si no se detectó)
- **name**: Nombre del host
- **os_name**: Sistema operativo
- **purpose**: Tipo de dispositivo

---

### Verificar Services Importados

```bash
msf6 > services

Services
========

host         port   proto  name          state  info
----         ----   -----  ----          -----  ----
10.10.10.40  135    tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  139    tcp    netbios-ssn   open   Microsoft Windows netbios-ssn
10.10.10.40  445    tcp    microsoft-ds  open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
10.10.10.40  49152  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49153  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49154  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49155  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49156  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49157  tcp    msrpc         open   Microsoft Windows RPC
```

**Columnas**:
- **host**: IP del host
- **port**: Puerto
- **proto**: Protocolo (tcp/udp)
- **name**: Nombre del servicio
- **state**: Estado (open/closed/filtered)
- **info**: Información adicional del servicio

---

## 🔍 Usar Nmap dentro de MSFconsole

### Comando: db_nmap

En lugar de salir de msfconsole o poner el proceso en background, podemos usar Nmap **directamente desde msfconsole**:

```bash
msf6 > db_nmap -sV -sS 10.10.10.8

[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-17 21:04 UTC
[*] Nmap: Nmap scan report for 10.10.10.8
[*] Nmap: Host is up (0.016s latency).
[*] Nmap: Not shown: 999 filtered ports
[*] Nmap: PORT   STATE SERVICE VERSION
[*] Nmap: 80/tcp open  http    HttpFileServer httpd 2.3
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 11.12 seconds
```

**Parámetros**:
- `-sV` = Detección de versión
- `-sS` = SYN scan (stealth)

**Ventajas**:
- ✅ No necesitas salir de msfconsole
- ✅ Resultados **automáticamente guardados** en la database
- ✅ Disponibles inmediatamente para usar

---

### Verificar Hosts Después de db_nmap

```bash
msf6 > hosts

Hosts
=====

address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------  ---------  -----  -------  ----  --------
10.10.10.8              Unknown                    device         
10.10.10.40             Unknown                    device         
```

**Observación**: Ahora tenemos **2 hosts** en la database

---

### Verificar Services Después de db_nmap

```bash
msf6 > services

Services
========

host         port   proto  name          state  info
----         ----   -----  ----          -----  ----
10.10.10.8   80     tcp    http          open   HttpFileServer httpd 2.3
10.10.10.40  135    tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  139    tcp    netbios-ssn   open   Microsoft Windows netbios-ssn
10.10.10.40  445    tcp    microsoft-ds  open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
10.10.10.40  49152  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49153  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49154  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49155  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49156  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49157  tcp    msrpc         open   Microsoft Windows RPC
```

**Nuevo servicio**: 
- Host **10.10.10.8** con **HttpFileServer httpd 2.3** en puerto 80

---

## 💾 Backup de Datos

### ¿Por Qué Hacer Backup?

Después de terminar una sesión, es importante **respaldar los datos** por si algo pasa con el servicio PostgreSQL.

### Comando: db_export

```bash
msf6 > db_export -h

Usage:
    db_export -f <format> [filename]
    Format can be one of: xml, pwdump
[-] No output file was specified
```

**Formatos soportados**:
- **xml**: Formato XML (recomendado)
- **pwdump**: Formato de volcado de passwords

---

### Exportar a XML

```bash
msf6 > db_export -f xml backup.xml

[*] Starting export of workspace default to backup.xml [ xml ]...
[*] Finished export of workspace default to backup.xml [ xml ]...
```

**Resultado**: 
- Archivo `backup.xml` creado
- Contiene **todo** el workspace `default`

### Importar Backup Después

```bash
msf6 > db_import backup.xml

[*] Importing 'Metasploit XML' data
[*] Import: Parsing with 'Nokogiri v1.10.9'
[*] Importing hosts
[*] Importing services
[*] Successfully imported backup.xml
```

**Uso**: Restaurar datos en caso de pérdida

---

## 🖥️ Gestión de Hosts

### Comando: hosts

El comando `hosts` muestra una tabla de database que se puebla automáticamente con:
- Direcciones de hosts
- Nombres de hosts
- Información del sistema operativo
- Otros detalles descubiertos

### Ayuda de Hosts

```bash
msf6 > hosts -h

Usage: hosts [ options ] [addr1 addr2 ...]

OPTIONS:
  -a,--add          Add the hosts instead of searching
  -d,--delete       Delete the hosts instead of searching
  -c <col1,col2>    Only show the given columns (see list below)
  -C <col1,col2>    Only show the given columns until the next restart (see list below)
  -h,--help         Show this help information
  -u,--up           Only show hosts which are up
  -o <file>         Send output to a file in CSV format
  -O <column>       Order rows by specified column number
  -R,--rhosts       Set RHOSTS from the results of the search
  -S,--search       Search string to filter by
  -i,--info         Change the info of a host
  -n,--name         Change the name of a host
  -m,--comment      Change the comment of a host
  -t,--tag          Add or specify a tag to a range of hosts

Available columns: address, arch, comm, comments, created_at, cred_count, 
detected_arch, exploit_attempt_count, host_detail_count, info, mac, name, 
note_count, os_family, os_flavor, os_lang, os_name, os_sp, purpose, scope, 
service_count, state, updated_at, virtual_host, vuln_count, tags
```

---

### Opciones Importantes de Hosts

| Opción | Descripción |
|--------|-------------|
| `-a, --add` | Agregar hosts en lugar de buscar |
| `-d, --delete` | Eliminar hosts |
| `-c <col1,col2>` | Mostrar solo columnas específicas |
| `-h, --help` | Mostrar ayuda |
| `-u, --up` | Mostrar solo hosts activos |
| `-o <file>` | Exportar output a CSV |
| `-O <column>` | Ordenar por columna específica |
| `-R, --rhosts` | Configurar RHOSTS desde resultados |
| `-S, --search` | Filtrar con string de búsqueda |
| `-i, --info` | Cambiar info de un host |
| `-n, --name` | Cambiar nombre de un host |
| `-m, --comment` | Agregar comentario a un host |
| `-t, --tag` | Agregar tag a rango de hosts |

---

### Columnas Disponibles

```
address, arch, comm, comments, created_at, cred_count, detected_arch, 
exploit_attempt_count, host_detail_count, info, mac, name, note_count, 
os_family, os_flavor, os_lang, os_name, os_sp, purpose, scope, 
service_count, state, updated_at, virtual_host, vuln_count, tags
```

### Ejemplos de Uso

```bash
# Ver solo hosts activos
msf6 > hosts -u

# Mostrar solo columnas específicas
msf6 > hosts -c address,os_name,service_count

# Exportar a CSV
msf6 > hosts -o hosts_backup.csv

# Configurar RHOSTS desde resultados
msf6 > hosts -R

# Buscar hosts específicos
msf6 > hosts -S 10.10.10

# Agregar comentario
msf6 > hosts -m "Servidor principal" 10.10.10.40
```

---

## 🔌 Gestión de Services

### Comando: services

El comando `services` funciona de la misma manera que `hosts`. Contiene una tabla con descripciones e información de servicios descubiertos.

### Ayuda de Services

```bash
msf6 > services -h

Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]

  -a,--add          Add the services instead of searching
  -d,--delete       Delete the services instead of searching
  -c <col1,col2>    Only show the given columns
  -h,--help         Show this help information
  -s <name>         Name of the service to add
  -p <port>         Search for a list of ports
  -r <protocol>     Protocol type of the service being added [tcp|udp]
  -u,--up           Only show services which are up
  -o <file>         Send output to a file in csv format
  -O <column>       Order rows by specified column number
  -R,--rhosts       Set RHOSTS from the results of the search
  -S,--search       Search string to filter by
  -U,--update       Update data for existing service

Available columns: created_at, info, name, port, proto, state, updated_at
```

---

### Opciones Importantes de Services

| Opción | Descripción |
|--------|-------------|
| `-a, --add` | Agregar servicios en lugar de buscar |
| `-d, --delete` | Eliminar servicios |
| `-c <col1,col2>` | Mostrar solo columnas específicas |
| `-h, --help` | Mostrar ayuda |
| `-s <name>` | Nombre del servicio a agregar |
| `-p <port>` | Buscar lista de puertos |
| `-r <protocol>` | Tipo de protocolo (tcp/udp) |
| `-u, --up` | Mostrar solo servicios activos |
| `-o <file>` | Exportar a CSV |
| `-O <column>` | Ordenar por columna |
| `-R, --rhosts` | Configurar RHOSTS desde resultados |
| `-S, --search` | Filtrar con string de búsqueda |
| `-U, --update` | Actualizar datos de servicio existente |

---

### Ejemplos de Uso

```bash
# Buscar servicios por puerto
msf6 > services -p 80,443,8080

# Buscar servicios HTTP
msf6 > services -S http

# Buscar solo servicios TCP
msf6 > services -r tcp

# Ver solo servicios activos
msf6 > services -u

# Configurar RHOSTS desde servicios SMB
msf6 > services -S smb -R

# Exportar servicios a CSV
msf6 > services -o services_backup.csv

# Mostrar solo columnas específicas
msf6 > services -c host,port,name,state
```

---

## 🔑 Gestión de Credentials

### Comando: creds

El comando `creds` permite visualizar las **credenciales recopiladas** durante las interacciones con el host objetivo.

También podemos:
- ✅ Agregar credenciales manualmente
- ✅ Asociar credenciales con especificaciones de puertos
- ✅ Agregar descripciones
- ✅ Filtrar y buscar credenciales

---

### Ayuda de Credentials

```bash
msf6 > creds -h

With no sub-command, list credentials. If an address range is
given, show only credentials with logins on hosts within that
range.

Usage - Listing credentials:
  creds [filter options] [address range]

Usage - Adding credentials:
  creds add uses the following named parameters.
    user      :  Public, usually a username
    password  :  Private, private_type Password.
    ntlm      :  Private, private_type NTLM Hash.
    Postgres  :  Private, private_type Postgres MD5
    ssh-key   :  Private, private_type SSH key, must be a file path.
    hash      :  Private, private_type Nonreplayable hash
    jtr       :  Private, private_type John the Ripper hash type.
    realm     :  Realm, 
    realm-type:  Realm, realm_type (domain db2db sid pgdb rsync wildcard), defaults to domain.
```

---

### Tipos de Credenciales

| Tipo | Descripción |
|------|-------------|
| **user** | Usuario (público) |
| **password** | Contraseña en texto plano |
| **ntlm** | Hash NTLM |
| **Postgres** | Hash MD5 de Postgres |
| **ssh-key** | Clave SSH (debe ser ruta de archivo) |
| **hash** | Hash no reproducible |
| **jtr** | Tipo de hash de John the Ripper |
| **realm** | Dominio/Realm |

---

### Ejemplos: Agregar Credenciales

```bash
# Agregar usuario, contraseña y realm
msf6 > creds add user:admin password:notpassword realm:workgroup

# Agregar usuario y contraseña
msf6 > creds add user:guest password:'guest password'

# Agregar solo contraseña
msf6 > creds add password:'password without username'

# Agregar usuario con hash NTLM
msf6 > creds add user:admin ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A

# Agregar solo hash NTLM
msf6 > creds add ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A

# Agregar hash MD5 de Postgres
msf6 > creds add user:postgres postgres:md5be86a79bf2043622d58d5453c47d4860

# Agregar usuario con clave SSH
msf6 > creds add user:sshadmin ssh-key:/path/to/id_rsa

# Agregar usuario con hash no reproducible
msf6 > creds add user:other hash:d19c32489b870735b5f587d76b934283 jtr:md5

# Agregar solo hash
msf6 > creds add hash:d19c32489b870735b5f587d76b934283
```

---

### Opciones de Filtrado

```bash
# Opciones generales
  -h,--help             Show this help information
  -o <file>             Send output to a file in csv/jtr (john the ripper) format.
                        If the file name ends in '.jtr', that format will be used.
                        If file name ends in '.hcat', the hashcat format will be used.
                        CSV by default.
  -d,--delete           Delete one or more credentials

# Filtros para listar
  -P,--password <text>  List passwords that match this text
  -p,--port <portspec>  List creds with logins on services matching this port spec
  -s <svc names>        List creds matching comma-separated service names
  -u,--user <text>      List users that match this text
  -t,--type <type>      List creds that match the following types: password,ntlm,hash
  -O,--origins <IP>     List creds that match these origins
  -R,--rhosts           Set RHOSTS from the results of the search
  -v,--verbose          Don't truncate long password hashes
```

---

### Tipos de Hash de John the Ripper

**Sistemas Operativos**:
```
Blowfish ($2a$)   : bf
BSDi     (_)      : bsdi
DES               : des,crypt
MD5      ($1$)    : md5
SHA256   ($5$)    : sha256,crypt
SHA512   ($6$)    : sha512,crypt
```

**Bases de Datos**:
```
MSSQL             : mssql
MSSQL 2005        : mssql05
MSSQL 2012/2014   : mssql12
MySQL < 4.1       : mysql
MySQL >= 4.1      : mysql-sha1
Oracle            : des,oracle
Oracle 11         : raw-sha1,oracle11
Oracle 11 (H type): dynamic_1506
Oracle 12c        : oracle12c
Postgres          : postgres,raw-md5
```

---

### Ejemplos: Listar Credenciales

```bash
# Listar todas las credenciales
msf6 > creds

# Credenciales con logins en este rango
msf6 > creds 1.2.3.4/24

# Credenciales con orígenes en este rango
msf6 > creds -O 1.2.3.4/24

# Credenciales en puertos específicos (formato nmap)
msf6 > creds -p 22-25,445

# Todas las credenciales asociadas con SSH o SMB
msf6 > creds -s ssh,smb

# Todas las credenciales NTLM
msf6 > creds -t NTLM

# Todos los hashes tipo MD5 de John the Ripper
msf6 > creds -j md5
```

---

### Ejemplo: Eliminar Credenciales

```bash
# Eliminar todas las credenciales SMB
msf6 > creds -d -s smb
```

---

### Exportar Credenciales

```bash
# Exportar a CSV
msf6 > creds -o credentials.csv

# Exportar a formato John the Ripper
msf6 > creds -o credentials.jtr

# Exportar a formato Hashcat
msf6 > creds -o credentials.hcat
```

---

## 💎 Gestión de Loot

### ¿Qué es Loot?

El **loot** se refiere a:
- Hash dumps de diferentes tipos de sistemas
- Archivos `hashes`
- Archivos `passwd`
- Archivos `shadow`
- Otros archivos valiosos extraídos

### Comando: loot

El comando `loot` funciona en conjunto con `creds` para ofrecer una **lista rápida** de servicios y usuarios comprometidos.

---

### Ayuda de Loot

```bash
msf6 > loot -h

Usage: loot [options]
 Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]
  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] -t [type]
  Del: loot -d [addr1 addr2 ...]

  -a,--add          Add loot to the list of addresses, instead of listing
  -d,--delete       Delete *all* loot matching host and type
  -f,--file         File with contents of the loot to add
  -i,--info         Info of the loot to add
  -t <type1,type2>  Search for a list of types
  -h,--help         Show this help information
  -S,--search       Search string to filter by
```

---

### Opciones de Loot

| Opción | Descripción |
|--------|-------------|
| `-a, --add` | Agregar loot a la lista de direcciones |
| `-d, --delete` | Eliminar TODO el loot que coincida con host y tipo |
| `-f, --file` | Archivo con contenidos del loot a agregar |
| `-i, --info` | Información del loot a agregar |
| `-t <type1,type2>` | Buscar lista de tipos |
| `-h, --help` | Mostrar ayuda |
| `-S, --search` | String de búsqueda para filtrar |

---

### Ejemplos de Uso

```bash
# Listar todo el loot
msf6 > loot

# Loot de hosts específicos
msf6 > loot 10.10.10.40

# Buscar tipos específicos de loot
msf6 > loot -t hashes,passwd

# Agregar loot manualmente
msf6 > loot -f /tmp/hashes.txt -i "NTLM hashes from DC" -a 10.10.10.50 -t ntlm_hashes

# Eliminar loot de un host
msf6 > loot -d 10.10.10.40

# Buscar loot específico
msf6 > loot -S password
```

---

## 🎯 Workflow Completo con Database

### Ejemplo Práctico: Pentest de Red

```bash
# 1. Crear workspace para el proyecto
msf6 > workspace -a Proyecto_Cliente_ABC
[*] Added workspace: Proyecto_Cliente_ABC

# 2. Escanear red objetivo
msf6 > db_nmap -sV -sC -p- 192.168.1.0/24
[*] Nmap: ... scanning ...

# 3. Ver hosts descubiertos
msf6 > hosts -u
# Lista de hosts activos

# 4. Ver servicios vulnerables
msf6 > services -S http,smb,ssh
# Servicios potencialmente explotables

# 5. Explotar un servicio
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > services -S microsoft-ds -R  # Configurar RHOSTS automáticamente
msf6 > exploit

# 6. Extraer credenciales
meterpreter > hashdump
msf6 > creds

# 7. Agregar notas
msf6 > hosts -m "DC principal - Windows Server 2012" 192.168.1.10

# 8. Exportar resultados
msf6 > db_export -f xml proyecto_abc_resultados.xml

# 9. Cambiar a otro workspace
msf6 > workspace default
```

---

## 📊 Integración con Herramientas Externas

### Herramientas Compatibles

Metasploit puede importar resultados de:

| Herramienta | Descripción |
|-------------|-------------|
| **Nmap** | Scanner de redes (XML) |
| **Nessus** | Vulnerability scanner (NBE/XML) |
| **Nexpose** | Vulnerability management (XML) |
| **OpenVAS** | Vulnerability scanner (XML) |
| **Burp Suite** | Web application scanner (XML) |
| **Acunetix** | Web vulnerability scanner (XML) |

### Ejemplo: Importar Scan de Nessus

```bash
# 1. Exportar resultados de Nessus como .nessus (XML)
# 2. Importar a Metasploit

msf6 > db_import /path/to/nessus_scan.nessus

[*] Importing 'Nessus XML (v2)' data
[*] Importing host 192.168.1.10
[*] Importing host 192.168.1.11
[*] Successfully imported /path/to/nessus_scan.nessus

# 3. Ver vulnerabilidades importadas
msf6 > vulns

Vulnerabilities
===============

host          port  name                  refs
----          ----  ----                  ----
192.168.1.10  445   MS17-010 EternalBlue  CVE-2017-0143,MS17-010
192.168.1.11  80    Apache 2.2.15 XSS     CVE-2010-1452
```

---

## 💡 Mejores Prácticas

### 1. Organización con Workspaces

```bash
# Crear workspaces por cliente/proyecto
workspace -a Cliente_A_Red_Interna
workspace -a Cliente_A_Red_DMZ
workspace -a Cliente_B_WebApp
```

### 2. Backup Regular

```bash
# Exportar al final de cada sesión
db_export -f xml backup_$(date +%Y%m%d_%H%M%S).xml
```

### 3. Usar db_nmap en Lugar de Nmap Externo

```bash
# ✅ BIEN - Resultados automáticamente en database
db_nmap -sV -sC 10.10.10.0/24

# ❌ NO IDEAL - Tienes que importar manualmente
# nmap -sV -sC -oX scan.xml 10.10.10.0/24
# db_import scan.xml
```

### 4. Aprovechar -R para Configuración Automática

```bash
# Configurar RHOSTS automáticamente desde servicios
services -S http -R
set payload windows/meterpreter/reverse_tcp
exploit
```

### 5. Agregar Comentarios y Tags

```bash
# Agregar comentarios a hosts importantes
hosts -m "Domain Controller" 192.168.1.10
hosts -m "Web Server - Production" 192.168.1.50

# Agregar tags para organización
hosts -t critical 192.168.1.10
hosts -t webserver 192.168.1.50
```

---

## 🔑 Comandos de Referencia Rápida

### Database Management

```bash
# Estado
db_status

# Conectar/Desconectar
db_connect <user>:<pass>@<host>:<port>/<database>
db_disconnect

# Reconstruir caché
db_rebuild_cache
```

### Workspaces

```bash
workspace                    # Listar
workspace -a <name>          # Crear
workspace <name>             # Cambiar
workspace -d <name>          # Eliminar
workspace -r <old> <new>     # Renombrar
```

### Import/Export

```bash
db_import <file>             # Importar scan
db_export -f xml <file>      # Exportar a XML
db_nmap <options> <target>   # Scan con Nmap
```

### Data Management

```bash
hosts                        # Listar hosts
hosts -R                     # Set RHOSTS
services                     # Listar servicios
services -S <term>           # Buscar servicios
creds                        # Listar credenciales
loot                         # Listar loot
vulns                        # Listar vulnerabilidades
notes                        # Listar notas
```

---

## 🎓 Resumen Ejecutivo

### Conceptos Clave

1. **Database** = Sistema de almacenamiento persistente para resultados de pentesting
2. **PostgreSQL** = Motor de database usado por Metasploit
3. **Workspaces** = Organización por proyecto/cliente/red
4. **db_nmap** = Escanear y guardar automáticamente en database
5. **hosts/services/creds/loot** = Comandos para gestionar diferentes tipos de datos

### Lo Que Aprendimos

✅ **Configurar** PostgreSQL y MSF database  
✅ **Crear y gestionar** workspaces  
✅ **Importar** resultados de scans externos  
✅ **Usar db_nmap** para scanning integrado  
✅ **Exportar** datos para backup  
✅ **Gestionar** hosts, services, credentials y loot  
✅ **Automatizar** configuración con -R  

### Ventajas de Usar Database

- 🎯 **Organización** de grandes cantidades de datos
- 🎯 **Persistencia** entre sesiones
- 🎯 **Automatización** de configuración de módulos
- 🎯 **Integración** con herramientas externas
- 🎯 **Reportes** y exportación de resultados
- 🎯 **Colaboración** entre miembros del equipo

---

## 📚 Recursos Adicionales

### Documentación Oficial
- https://docs.metasploit.com/docs/using-metasploit/intermediate/using-databases.html
- https://github.com/rapid7/metasploit-framework/wiki/Using-the-Database

### Configuración Avanzada
- https://www.offensive-security.com/metasploit-unleashed/using-databases/
- https://www.rapid7.com/blog/post/2010/06/14/managing-your-metasploit-data/

---

**¡Las databases son esenciales para pentests organizados y profesionales!** 🚀
