# Comunicación con procesos

Uno de los mejores lugares para buscar escalada de privilegios son los procesos que se están ejecutando en el sistema. Incluso si un proceso no se está ejecutando como administrador, puede conducir a privilegios adicionales. El ejemplo más común es descubrir un servidor web como `IIS` o `XAMPP` ejecutándose en la máquina, colocar un shell `aspx`/`php` en el equipo y conseguir una shell como el usuario que ejecuta el servidor web. Aunque este usuario normalmente no tiene privilegios de administrador, suele disponer del privilegio `SeImpersonate`, lo que permite aprovechar técnicas como `RoguePotato`, `JuicyPotato` o `LonelyPotato` para escalar privilegios y obtener una sesión con permisos de `SYSTEM`.

`SeImpersonate`: Permite actuar como otro usuario. Estos privilegios están en los tokens de acceso que Windows asigna a cada proceso.

## Tokens de acceso

En Windows, los [**tokens de acceso**](https://learn.microsoft.com/es-es/windows/win32/secauthz/access-tokens) se usan para describir el contexto de seguridad (atributos o reglas de seguridad) de un proceso o hilo. El token incluye información sobre la identidad de la cuenta de usuario y los privilegios relacionados con un proceso o hilo específico. Cuando un usuario se autentica en un sistema, su contraseña se verifica contra una base de datos de seguridad y, si la autenticación es correcta, se le asigna un token de acceso. Cada vez que un usuario interactúa con un proceso, se presenta una copia de este token para determinar su nivel de privilegios (ese proceso hereda el token del usuario que lo ejecuta).

## Enumeración de servicios de red

La forma más común en que la gente interactúa con procesos es a través de un socket de red (DNS, HTTP, SMB, etc.). El comando [`netstat`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) mostrará conexiones TCP y UDP activas y nos dará una mejor idea de qué servicios están escuchando en qué puertos, tanto localmente como accesibles desde el exterior. Podemos encontrar un servicio vulnerable accesible sólo desde localhost (cuando estamos conectados al host) que podamos explotar para escalar privilegios.

### Mostrar conexiones de red activas

```
C:\htb> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       3812
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       836
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       936
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       5044
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       528
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       996
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1260
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2008
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       600
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       1888
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING       616
  TCP    10.129.43.8:139        0.0.0.0:0              LISTENING       4
  TCP    10.129.43.8:3389       10.10.14.3:63191       ESTABLISHED     936
  TCP    10.129.43.8:49671      40.67.251.132:443      ESTABLISHED     1260
  TCP    10.129.43.8:49773      52.37.190.150:443      ESTABLISHED     2608
  TCP    10.129.43.8:51580      40.67.251.132:443      ESTABLISHED     3808
  TCP    10.129.43.8:54267      40.67.254.36:443       ESTABLISHED     3808
  TCP    10.129.43.8:54268      40.67.254.36:443       ESTABLISHED     1260
  TCP    10.129.43.8:54269      64.233.184.189:443     ESTABLISHED     2608
  TCP    10.129.43.8:54273      216.58.210.195:443     ESTABLISHED     2608
  TCP    127.0.0.1:14147        0.0.0.0:0              LISTENING       3812

<SNIP>

  TCP    192.168.20.56:139      0.0.0.0:0              LISTENING       4
  TCP    [::]:21                [::]:0                 LISTENING       3812
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       836
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3389              [::]:0                 LISTENING       936
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       5044
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       528
  TCP    [::]:49665             [::]:0                 LISTENING       996
  TCP    [::]:49666             [::]:0                 LISTENING       1260
  TCP    [::]:49668             [::]:0                 LISTENING       2008
  TCP    [::]:49669             [::]:0                 LISTENING       600
  TCP    [::]:49670             [::]:0                 LISTENING       1888
  TCP    [::]:49674             [::]:0                 LISTENING       616
  TCP    [::1]:14147            [::]:0                 LISTENING       3812
  UDP    0.0.0.0:123            *:*                                    1104
  UDP    0.0.0.0:500            *:*                                    1260
  UDP    0.0.0.0:3389           *:*                                    936

<SNIP>
```

Lo principal a observar en las conexiones de red activas son las entradas que escuchan en direcciones `loopback` (`127.0.0.1` y `::1`) y que **no** están escuchando en la IP pública del host (por ejemplo `10.129.43.8`) ni en broadcast (`0.0.0.0`, `::/0`, todas las interfaces). El motivo es que los `sockets` en `localhost` a menudo se consideran incorrectamente seguros por la suposición de que “no son accesibles desde la red”. El que destaca inmediatamente aquí es el puerto **14147**, que se usa para la interfaz administrativa de FileZilla. Conectándose a este puerto puede ser posible extraer contraseñas FTP y también crear un share FTP en `C:\` como el usuario del servicio FileZilla (potencialmente Administrator).

## Más ejemplos

Un buen ejemplo de esta clase de escalada es `Splunk Universal Forwarder`, instalado en endpoints para enviar logs a `Splunk`. La configuración por defecto de `Splunk` no tenía autenticación y permitía a cualquiera desplegar aplicaciones, lo que podía conducir a ejecución de código. Además, Splunk por defecto solía ejecutarse como `SYSTEM` y no como un usuario con pocos privilegios. Para más información ver [`Splunk Universal Forwarder Hijacking`](https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2)  o [`SplunkWhisperer2`](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/).

Otro vector común es el puerto Erlang (25672). Erlang (p. ej. RabbitMQ) usa un "cookie" para unirse al clúster; muchos productos usan cookies débiles (RabbitMQ usa `rabbit` por defecto) o almacenan la cookie en un fichero con permisos laxos. Aplicaciones ejemplo: SolarWinds, RabbitMQ, CouchDB. Para más información ver el blog de [Mubix](https://malicious.link/posts/2018/erlang-arce/) sobre Erlang-arce.

## Named Pipes

La otra forma en que los procesos se comunican con cada uno es mediante **Named Pipes**. Las pipes son esencialmente ficheros almacenados en memoria que se borran tras su lectura. Es decir, es una pipe especial con un nombre y persistencia temporal en el sistema, lo que permite que dos procesos distintos (incluso en sesiones diferentes o equipos distintos) se comuniquen a través de ese nombre. Cobalt Strike usa Named Pipes para cada comando (excluyendo [BOF](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)). El flujo básico es:

* Beacon crea una named pipe `\\.\\pipe\\msagent_12`
* Beacon inicia un nuevo proceso e inyecta el comando en ese proceso direccionando la salida a `\\.\\pipe\\msagent_12`
* El servidor muestra lo que se escribió en `\\.\\pipe\\msagent_12`

Cobalt Strike hace esto para que si el comando es detectado o falla, no afecte al beacon (proceso que corre el comando). A menudo los usuarios cambian el nombre de sus pipes para hacerse pasar por otra aplicación (por ejemplo `mojo` en lugar de `msagent`). Un hallazgo interesante fue encontrar una pipe que empezaba con `mojo` en una máquina que no tenía Chrome instalado; resultó ser el equipo del red team interno.

### Más sobre Named Pipes

Las pipes se usan para comunicación entre dos aplicaciones o procesos que utilizan memoria compartida. Hay dos tipos: [`named pipes`](https://learn.microsoft.com/es-es/windows/win32/ipc/named-pipes) y `anonymous pipe`s. Un ejemplo de `named pipe` es `\\.\\PipeName\\ExampleNamedPipeServer`. Windows usa una implementación cliente‑servidor para la comunicación por pipes: el proceso que crea la pipe es el servidor y el proceso que se comunica es el cliente. Las pipes pueden ser `half‑duplex` (unidireccional, sólo el cliente puede enviar datos a través de) o `duplex` (bidireccional, también el servidor puede responder con datos a través de la pipe). Cada conexión activa a un servidor de pipes genera la creación de una nueva pipe; todas comparten el mismo nombre pero usan buffers de datos distintos.

Podemos usar la herramienta [**PipeList**](https://learn.microsoft.com/es-es/sysinternals/downloads/pipelist) de [`Sysinternals`](https://learn.microsoft.com/es-es/sysinternals/) para enumerar instancias de named pipes.

### Listar Named Pipes con Pipelist

```
C:\htb> pipelist.exe /accepteula

PipeList v1.02 - Lists open named pipes
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Pipe Name                                    Instances       Max Instances
---------                                    ---------       -------------
InitShutdown                                      3               -1
lsass                                             4               -1
ntsvcs                                            3               -1
scerpc                                            3               -1
Winsock2\\CatalogChangeListener-340-0              1                1
Winsock2\\CatalogChangeListener-414-0              1                1
epmapper                                          3               -1
Winsock2\\CatalogChangeListener-3ec-0              1                1
Winsock2\\CatalogChangeListener-44c-0              1                1
LSM_API_service                                   3               -1
atsvc                                             3               -1
Winsock2\\CatalogChangeListener-5e0-0              1                1
eventlog                                          3               -1
Winsock2\\CatalogChangeListener-6a8-0              1                1
spoolss                                           3               -1
vmware-usbarbpipe                                 5               -1
srvsvc                                            4               -1
ROUTER                                            3               -1
vmware-authdpipe                                  1                1

<SNIP>
```

Además, podemos usar `PowerShell` para enumerar las `named pipes` usando gci (Get-ChildItem):

```
PS C:\htb>  gci \\.\pipe\


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 InitShutdown
------       12/31/1600   4:00 PM              4 lsass
------       12/31/1600   4:00 PM              3 ntsvcs
------       12/31/1600   4:00 PM              3 scerpc


    Directory: \\.\pipe\Winsock2


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-34c-0


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 epmapper

<SNIP>
```

---
---

# Análisis de permisos en Named Pipes con AccessChk

Después de obtener un listado de las **Named Pipes** activas en el sistema, el siguiente paso consiste en **analizar los permisos** que tiene cada una. Para ello utilizamos la herramienta [**AccessChk**](https://learn.microsoft.com/es-es/sysinternals/downloads/accesschk), parte de la suite Sysinternals creada por *Mark Russinovich*. Esta utilidad permite revisar la **Discretionary Access Control List (DACL)** de un objeto, es decir, la lista que define **quién puede leer, escribir, modificar o ejecutar** sobre un recurso.

---

## Revisión de permisos con AccessChk

Podemos usar el siguiente comando para revisar las DACLs de todas las Named Pipes del sistema:

```bash
accesschk.exe /accepteula \\pipe\* -v
```

Y si deseamos examinar una pipe en particular, basta con especificar su nombre:

```bash
accesschk.exe /accepteula \\.\Pipe\<nombre_de_la_pipe> -v
```

Este comando nos mostrará qué usuarios o grupos poseen permisos sobre la pipe, así como el nivel de acceso (lectura, escritura, control total, etc.).

---

## 🔍 Revisión de la Named Pipe del proceso LSASS

Como ejemplo, revisaremos los permisos de la Named Pipe **LSASS** (*Local Security Authority Subsystem Service*), un proceso crítico encargado de manejar autenticaciones, tokens y políticas de seguridad del sistema.

### Comando ejecutado:

```bash
C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v
```

**Salida parcial:**

```
\\.\Pipe\lsass
  Untrusted Mandatory Level [No-Write-Up]
  RW Everyone
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW NT AUTHORITY\ANONYMOUS LOGON
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
```

### Interpretación:

* Los grupos **Everyone**, **Anonymous Logon** y **Application Package Authority** tienen permisos de lectura y escritura básicos, pero no control total.
* Solo el grupo **Administrators** posee `FILE_ALL_ACCESS`, lo que significa **acceso completo** a la Named Pipe.

📘 **Conclusión:** los permisos del proceso LSASS están correctamente configurados; solo los administradores pueden manipular o modificar este canal de comunicación.

---

## Ejemplo de ataque: Named Pipe expuesta

Un caso interesante ocurre cuando una Named Pipe presenta **permisos demasiado amplios**, permitiendo que usuarios no privilegiados puedan escribir o ejecutar sobre ella. Este tipo de configuración puede abrir la puerta a una **escalada de privilegios**.

Consideremos el ejemplo de la Named Pipe **WindscribeService**, perteneciente al servicio de la VPN Windscribe. Mediante AccessChk, podemos buscar pipes con permisos de escritura usando:

```bash
accesschk.exe -accepteula -w \\pipe\* -v
```

En la salida, observamos que la pipe `WindscribeService` permite acceso de **lectura y escritura al grupo Everyone**, es decir, a todos los usuarios autenticados del sistema.

### Comprobación específica:

```bash
C:\htb> accesschk.exe -accepteula -w \\pipe\WindscribeService -v
```

**Salida parcial:**

```
\\.\Pipe\WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
```

### Análisis:

* La DACL indica que el grupo **Everyone** tiene `FILE_ALL_ACCESS`, lo que significa **todos los permisos posibles** sobre la pipe: leer, escribir, modificar e incluso ejecutar.
* Dado que el servicio asociado a esta pipe corre con privilegios **SYSTEM**, un atacante podría **inyectar comandos o datos maliciosos** a través de la pipe y obtener **ejecución de código con privilegios de sistema**.


---
---
