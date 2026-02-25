# MySQL 

---

## 1. ¿Qué es MySQL?

**MySQL** es un **sistema de gestión de bases de datos relacional** (RDBMS) **open-source**, desarrollado y mantenido por **Oracle**.

Una **base de datos** es, en términos simples, una colección **estructurada** de datos, organizada para:

* Guardar información de forma ordenada
* Consultarla rápidamente
* Modificarla cuando sea necesario

En un RDBMS como MySQL, la información se almacena principalmente en **tablas**, que tienen:

* **Columnas** (campos / atributos)
* **Filas** (registros)
* **Tipos de dato** (texto, número, fecha, etc.)

MySQL está diseñado para manejar grandes volúmenes de datos de manera eficiente.


[Curso brebe MySql](https://www.w3schools.com/sql/sql_intro.asp)

---

## 2. Modelo Cliente–Servidor

MySQL funciona con el modelo **cliente-servidor**:

* **MySQL Server**: el servicio que corre en el host y gestiona la base de datos.
* **MySQL Client(s)**: herramientas o programas que se conectan al servidor para ejecutar consultas.

### 2.1 ¿Qué hace el servidor?

El servidor MySQL:

* Escucha conexiones en un puerto TCP (normalmente 3306)
* Autentica usuarios
* Aplica permisos
* Ejecuta consultas SQL
* Devuelve resultados

### 2.2 ¿Qué hace un cliente?

Un cliente MySQL permite:

* Insertar datos
* Borrar datos
* Modificar datos
* Consultar datos

Todo esto se hace usando el lenguaje **SQL**.

---

## 3. Ejemplo práctico: WordPress

Un ejemplo clásico de uso de MySQL es **WordPress**.

WordPress guarda en una base de datos:

* Publicaciones
* Usuarios
* Contraseñas (en general hasheadas)
* Configuraciones

En instalaciones seguras, la base de datos solo debería ser accesible desde:

* **localhost**

Sin embargo, en infraestructuras distribuidas, puede haber:

* Servidor web en una máquina
* Base de datos en otra máquina

Y ahí se vuelve relevante la superficie de ataque: si MySQL queda accesible desde red interna o Internet.

---

## 4. ¿Dónde se guardan las bases?

Los datos suelen almacenarse en:

* Directorios internos (por ejemplo `/var/lib/mysql`)
* Archivos de respaldo/exportación con extensión `.sql`

Ejemplo mencionado:

* `wordpress.sql`

⚠️ Importante: un archivo `.sql` suele contener **SQL plano** (CREATE TABLE, INSERT, etc.). Si un atacante accede a un dump, puede recuperar datos sensibles.

---

## 5. LAMP / LEMP

MySQL es muy usado en sitios web dinámicos y suele verse en stacks como:

* [**LAMP**](https://en.wikipedia.org/wiki/LAMP_(software_bundle)): Linux + Apache + MySQL + PHP
* [**LEMP**](https://lemp.io/): Linux + Nginx + MySQL + PHP

En hosting web, MySQL actúa como el “repositorio central” de datos que consumen scripts PHP.

Ejemplos de datos típicos almacenados:

* Usuarios
* Emails
* Permisos
* Contraseñas
* Contenido de formularios
* Valores internos y configuraciones

Nota: MySQL puede almacenar contraseñas en texto plano, pero lo normal es que la app (PHP) las **hashee** antes ([one-way encryption](https://en.citizendium.org/wiki/One-way_encryption)).

---

## 6. Comandos SQL y su impacto

Las consultas SQL son instrucciones que el motor ejecuta para:

* Mostrar datos (`SELECT`)
* Insertar (`INSERT`)
* Actualizar (`UPDATE`)
* Borrar (`DELETE`)
* Administrar estructura (`CREATE`, `ALTER`, `DROP`)
* Administrar usuarios y permisos

En aplicaciones web, un error SQL puede revelar información.

Esto es relevante porque:

* Errores SQL detallados confirman interacción con DB
* Mensajes de error pueden filtrar estructura, tablas, columnas
* Esto se explota con **SQL Injection**

---

## 7. MySQL vs MariaDB

**MariaDB** es un fork de MySQL.

Surgió cuando MySQL AB fue adquirida por Oracle y el desarrollador principal impulsó un proyecto abierto basado en el mismo código.

En muchos sistemas Linux, el comando `mysql` puede conectarte a un servidor MariaDB o MySQL sin que lo notes por fuera (hasta ver el banner).

---

# 8. Configuración por Defecto

La configuración de bases de datos es un tema enorme (existe el rol de **DBA** dedicado a esto).

La recomendación práctica es montar un laboratorio local:

* Instalar MySQL/MariaDB
* Probar configuraciones
* Ver cómo cambian comportamientos

---

## 8.1 Instalación y configuración por defecto (salida completa)

```bash
sudo apt install mysql-server -y
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

Salida:

```ini
[client]
port		= 3306
socket		= /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
nice		= 0

[mysqld]
skip-host-cache
skip-name-resolve
user		= mysql
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
port		= 3306
basedir		= /usr
datadir		= /var/lib/mysql
tmpdir		= /tmp
lc-messages-dir	= /usr/share/mysql
explicit_defaults_for_timestamp

symbolic-links=0

!includedir /etc/mysql/conf.d/
```

---


# 🔎 Estructura General del Archivo

El archivo está dividido en **secciones** indicadas por encabezados entre corchetes:

```
[client]
[mysqld_safe]
[mysqld]
```

Cada sección aplica a un componente distinto del ecosistema MySQL.

---

# 🖥️ 1️⃣ Sección `[client]`

Esta sección define parámetros para los clientes que se conectan al servidor MySQL (por ejemplo: `mysql`, `mysqldump`, scripts, aplicaciones, etc.).

```
[client]
port = 3306
socket = /var/run/mysqld/mysqld.sock
```

## 🔹 port = 3306

* Es el puerto TCP en el que el cliente intentará conectarse.
* **3306 es el puerto estándar de MySQL.**
* Si el servidor escucha en otro puerto, el cliente debe especificarlo.

⚠️ En auditorías de seguridad, encontrar 3306 expuesto a Internet puede indicar una mala configuración.

## 🔹 socket = /var/run/mysqld/mysqld.sock

* Es el archivo de socket Unix.
* Se usa para conexiones locales (sin usar TCP/IP).
* Es más rápido y seguro para conexiones dentro del mismo servidor.

Ejemplo:

```
mysql -u root -p --socket=/var/run/mysqld/mysqld.sock
```

---

# 🛡️ 2️⃣ Sección `[mysqld_safe]`

`mysqld_safe` es un wrapper que inicia el servidor MySQL y lo reinicia si se cae.

```
[mysqld_safe]
pid-file = /var/run/mysqld/mysqld.pid
socket = /var/run/mysqld/mysqld.sock
nice = 0
```

## 🔹 pid-file

* Guarda el ID del proceso (PID) del servidor.
* Permite al sistema controlar el servicio.
* Ejemplo: detenerlo con `kill`.

## 🔹 socket

* Debe coincidir con el definido en otras secciones.

## 🔹 nice = 0

* Define la prioridad del proceso en el sistema Linux.
* 0 = prioridad normal.
* Valores positivos → menor prioridad.
* Valores negativos → mayor prioridad.

---

# 🧠 3️⃣ Sección `[mysqld]` (La más importante)

Esta sección define cómo se comporta el servidor MySQL.

```
[mysqld]
skip-host-cache
skip-name-resolve
user = mysql
pid-file = /var/run/mysqld/mysqld.pid
socket = /var/run/mysqld/mysqld.sock
port = 3306
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql
explicit_defaults_for_timestamp
symbolic-links = 0
```

---

## 🔹 skip-host-cache

* Desactiva la caché de resolución de host.
* Reduce problemas cuando cambian IPs.
* Mejora estabilidad en ciertos entornos dinámicos.

---

## 🔹 skip-name-resolve

* MySQL no intentará resolver nombres DNS.
* Solo trabajará con direcciones IP.

### 🎯 Ventajas:

* Mejora rendimiento.
* Reduce dependencia de DNS.
* Evita retrasos si el DNS falla.

### 🔐 En seguridad:

Implica que los permisos deben definirse por IP y no por hostname.

Ejemplo válido:

```
GRANT ALL ON db.* TO 'user'@'192.168.1.%';
```

---

## 🔹 user = mysql

* Usuario del sistema Linux con el que corre el servicio.
* Buenas prácticas: nunca correr MySQL como root.
* Reduce impacto ante una posible explotación.

---

## 🔹 port = 3306

* Puerto en el que escucha el servidor.
* Puede modificarse por seguridad ("security through obscurity", aunque no reemplaza controles reales).

---

## 🔹 basedir = /usr

* Directorio base donde está instalado MySQL.
* Contiene binarios y librerías.

---

## 🔹 datadir = /var/lib/mysql

* Carpeta donde se almacenan las bases de datos.
* Cada base de datos es un subdirectorio.
* Cada tabla puede ser un archivo físico.

📁 Ejemplo típico:

```
/var/lib/mysql/
  ├── mysql/
  ├── information_schema/
  ├── mi_base_de_datos/
```

🔐 Desde perspectiva ofensiva:
Si un atacante logra escribir archivos aquí, puede comprometer completamente la base de datos.

---

## 🔹 tmpdir = /tmp

* Directorio para archivos temporales.
* Usado para operaciones como ORDER BY grandes o joins complejos.

⚠️ Si `/tmp` tiene permisos inseguros, podría haber vectores de abuso.

---

## 🔹 lc-messages-dir

* Directorio de mensajes de error.
* Define localización e idioma.

---

## 🔹 explicit_defaults_for_timestamp

* Obliga a definir explícitamente valores por defecto para columnas TIMESTAMP.
* Mejora consistencia.

---

## 🔹 symbolic-links = 0

* Desactiva enlaces simbólicos.

🔐 Importante en seguridad:
Evita ataques donde se usan symlinks para redirigir archivos sensibles.

---

# 📂 Directiva Final

```
!includedir /etc/mysql/conf.d/
```

* Incluye configuraciones adicionales.
* Permite modularizar configuración.
* Muchas veces aquí se agregan parámetros personalizados.

---

# 🔐 Perspectiva de Pentesting

Cuando auditamos MySQL, estos parámetros nos permiten inferir:

* Si escucha solo local o remotamente.
* Dónde están almacenados los datos.
* Si depende de DNS.
* Qué usuario del sistema ejecuta el servicio.
* Posibles vectores locales (tmpdir, datadir, permisos).

---



---

# 9. Dangerous Settings (Configuraciones Peligrosas)

Hay muchas opciones que pueden quedar mal configuradas. Las más relevantes desde seguridad:

| Setting            | Descripción                                    | Riesgo principal                                                                                 |
| ------------------ | ---------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `user`             | Define con qué usuario corre el servicio MySQL | Si corre como un usuario incorrecto o con permisos excesivos, aumenta el impacto ante compromiso |
| `password`         | Password del usuario MySQL                     | Puede quedar en texto plano en archivos de config o scripts                                      |
| `admin_address`    | IP donde escucha conexiones administrativas    | Si expone una interfaz administrativa a redes no confiables, amplía superficie de ataque         |
| `debug`            | Configuración de debug activa                  | Puede mostrar información sensible (rutas, queries, estados)                                     |
| `sql_warnings`     | Controla warnings en inserts                   | Puede filtrar información extra ante errores                                                     |
| `secure_file_priv` | Limita import/export de archivos               | Si está mal configurado, puede permitir leer/escribir archivos desde el servidor                 |

### 9.1 Por qué `user`, `password`, `admin_address` son críticos

Porque muchas veces quedan **en texto plano**, y si el atacante logra:

* Leer archivos (LFI, path traversal)
* Obtener shell

podría recuperar credenciales del servidor DB.

Con credenciales válidas, un atacante puede:

* Ver bases completas
* Exfiltrar datos personales
* Modificar registros (impacto de integridad)

### 9.2 Debug y mensajes de error

`debug` y `sql_warnings` pueden ser útiles para el administrador, pero peligrosos si:

* Se exponen en una app web
* La app devuelve errores completos

Esto puede facilitar:

* Enumeración de tablas/columnas
* Confirmación de SQLi
* Escalada a técnicas más avanzadas (SQL Injection)

Más [opciones](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html) de configuración.

---


Footprinting the Service
There are many reasons why a MySQL server could be accessed from an external network. Nevertheless, it is far from being one of the best practices, and we can always find databases that we can reach. Often, these settings were only meant to be temporary but were forgotten by the administrators. This server setup could also be used as a workaround due to a technical problem. Usually, the MySQL server runs on TCP port 3306, and we can scan this port with Nmap to get more detailed information.

Scanning MySQL Server
  MySQL
CyberWolfSec@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 00:53 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE     VERSION
3306/tcp open  nagios-nsca Nagios NSCA
| mysql-brute: 
|   Accounts: 
|     root:<empty> - Valid credentials
|_  Statistics: Performed 45010 guesses in 5 seconds, average tps: 9002.0
|_mysql-databases: ERROR: Script execution failed (use -d to debug)
|_mysql-dump-hashes: ERROR: Script execution failed (use -d to debug)
| mysql-empty-password: 
|_  root account has empty password
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.26-0ubuntu0.20.04.1
|   Thread ID: 13
|   Capabilities flags: 65535
|   Some Capabilities: SupportsLoadDataLocal, SupportsTransactions, Speaks41ProtocolOld, LongPassword, DontAllowDatabaseTableColumn, Support41Auth, IgnoreSigpipes, SwitchToSSLAfterHandshake, FoundRows, InteractiveClient, Speaks41ProtocolNew, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, LongColumnFlag, SupportsCompression, ODBCClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: YTSgMfqvx\x0F\x7F\x16\&\x1EAeK>0
|_  Auth Plugin Name: caching_sha2_password
|_mysql-users: ERROR: Script execution failed (use -d to debug)
|_mysql-variables: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.21 seconds
As with all our scans, we must be careful with the results and manually confirm the information obtained because some of the information might turn out to be a false-positive. This scan above is an excellent example of this, as we know for a fact that the target MySQL server does not use an empty password for the user root, but a fixed password. We can test this with the following command:

Interaction with the MySQL Server
  MySQL
CyberWolfSec@htb[/htb]$ mysql -u root -h 10.129.14.132

ERROR 1045 (28000): Access denied for user 'root'@'10.129.14.1' (using password: NO)
For example, if we use a password that we have guessed or found through our research, we will be able to log in to the MySQL server and execute some commands.

  MySQL
CyberWolfSec@htb[/htb]$ mysql -u root -pP4SSw0rd -h 10.129.14.128

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 150165
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)                                                         
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.                                     
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.                           
      
MySQL [(none)]> show databases;                                                                          
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
4 rows in set (0.006 sec)


MySQL [(none)]> select version();
+-------------------------+
| version()               |
+-------------------------+
| 8.0.27-0ubuntu0.20.04.1 |
+-------------------------+
1 row in set (0.001 sec)


MySQL [(none)]> use mysql;
MySQL [mysql]> show tables;
+------------------------------------------------------+
| Tables_in_mysql                                      |
+------------------------------------------------------+
| columns_priv                                         |
| component                                            |
| db                                                   |
| default_roles                                        |
| engine_cost                                          |
| func                                                 |
| general_log                                          |
| global_grants                                        |
| gtid_executed                                        |
| help_category                                        |
| help_keyword                                         |
| help_relation                                        |
| help_topic                                           |
| innodb_index_stats                                   |
| innodb_table_stats                                   |
| password_history                                     |
...SNIP...
| user                                                 |
+------------------------------------------------------+
37 rows in set (0.002 sec)
If we look at the existing databases, we will see several already exist. The most important databases for the MySQL server are the system schema (sys) and information schema (information_schema). The system schema contains tables, information, and metadata necessary for management. More about this database can be found in the reference manual of MySQL.

  MySQL
mysql> use sys;
mysql> show tables;  

+-----------------------------------------------+
| Tables_in_sys                                 |
+-----------------------------------------------+
| host_summary                                  |
| host_summary_by_file_io                       |
| host_summary_by_file_io_type                  |
| host_summary_by_stages                        |
| host_summary_by_statement_latency             |
| host_summary_by_statement_type                |
| innodb_buffer_stats_by_schema                 |
| innodb_buffer_stats_by_table                  |
| innodb_lock_waits                             |
| io_by_thread_by_latency                       |
...SNIP...
| x$waits_global_by_latency                     |
+-----------------------------------------------+


mysql> select host, unique_users from host_summary;

+-------------+--------------+                   
| host        | unique_users |                   
+-------------+--------------+                   
| 10.129.14.1 |            1 |                   
| localhost   |            2 |                   
+-------------+--------------+                   
2 rows in set (0,01 sec)  
The information schema is also a database that contains metadata. However, this metadata is mainly retrieved from the system schema database. The reason for the existence of these two is the ANSI/ISO standard that has been established. System schema is a Microsoft system catalog for SQL servers and contains much more information than the information schema.

Some of the commands we should remember and write down for working with MySQL databases are described below in the table.

Command	Description
mysql -u <user> -p<password> -h <IP address>	Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.
show databases;	Show all databases.
use <database>;	Select one of the existing databases.
show tables;	Show all available tables in the selected database.
show columns from <table>;	Show all columns in the selected table.
select * from <table>;	Show everything in the desired table.
select * from <table> where <column> = "<string>";	Search for needed string in the desired table.
We must know how to interact with different databases. Therefore, we recommend installing and configuring a MySQL server on one of our VMs for experimentation. There is also a widely covered security issues section in the reference manual that covers best practices for securing MySQL servers. We should use this when setting up our MySQL server to understand better why something might not work.

---

# Preeguntas


#### Enumerar el servidor MySQL y determinar la versión en uso. (Formato: MySQL XXXX)


#### Durante nuestra prueba de penetración, encontramos credenciales débiles "robin:robin". Deberíamos probarlas con el servidor MySQL. ¿Cuál es la dirección de correo electrónico del cliente "Otto Lang"?
