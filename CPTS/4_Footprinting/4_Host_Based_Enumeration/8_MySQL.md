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


# 🛠️ Footprinting y Enumeración del Servicio MySQL


---

# 1️⃣ Exposición del Servicio MySQL

MySQL generalmente escucha en:

```
TCP/3306
```

## 🔎 ¿Por qué puede estar expuesto?

Aunque no es buena práctica exponerlo a Internet, suele ocurrir por:

* Configuraciones temporales olvidadas
* Problemas técnicos que llevaron a "workarounds"
* Reglas de firewall mal implementadas
* Arquitecturas legacy
* Entornos de desarrollo migrados a producción

⚠️ En producción, MySQL debería:

* Escuchar solo en `127.0.0.1`
* Estar detrás de una VPN
* Estar protegido por reglas de firewall estrictas

---

# 2️⃣ Enumeración con Nmap y Scripts NSE

```bash
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

## 🔍 Qué estamos haciendo exactamente

| Flag            | Función                                              |
| --------------- | ---------------------------------------------------- |
| -sV             | Detección de versión                                 |
| -sC             | Scripts default                                      |
| -p3306          | Puerto específico                                    |
| --script mysql* | Ejecuta todos los scripts NSE relacionados con MySQL |

---

# 3️⃣ Análisis Técnico de la Salida

## 🧠 3.1 Detección de Servicio

```
3306/tcp open nagios-nsca Nagios NSCA
```

⚠️ Aquí vemos un posible **service misidentification**.

Nmap puede confundir servicios cuando:

* El banner no es claro
* El servicio responde parcialmente
* Hay middleboxes

Siempre validar manualmente.

---

## 🔐 3.2 mysql-brute

Indica credenciales válidas con password vacío:

```
root:<empty> - Valid credentials
```

⚠️ Esto puede ser un falso positivo.

¿Por qué?

* Algunos servidores responden diferente al handshake.
* El script interpreta ciertas respuestas como éxito.

Regla de oro en pentesting:

> Nunca confiar ciegamente en herramientas automatizadas.

---

## 🔎 3.3 mysql-info

Información extremadamente valiosa:

* Protocol: 10
* Version: 8.0.26
* Auth Plugin: caching_sha2_password
* Capabilities Flags
* Salt (usado en el handshake de autenticación)

### 🎯 Importancia del plugin de autenticación

`caching_sha2_password` es el método moderno por defecto en MySQL 8.

Implica:

* No usa el antiguo `mysql_native_password`
* Dificulta ciertos ataques offline
* Cambia comportamiento de autenticación en clientes antiguos

---

# 4️⃣ Validación Manual (Paso Crítico)

## 4.1 Intento sin contraseña

```bash
mysql -u root -h 10.129.14.132
```

Resultado:

```
ERROR 1045 (28000): Access denied
```

Esto confirma:

* El servicio responde correctamente
* Requiere autenticación
* No acepta password vacío

---

# 5️⃣ Acceso con Credenciales Válidas

```bash
mysql -u root -pP4SSw0rd -h 10.129.14.128
```

Una vez dentro, comienza la fase de **enumeración interna**.

---

# 6️⃣ Bases de Datos Críticas del Sistema

```sql
show databases;
```

Resultado:

* information_schema
* mysql
* performance_schema
* sys

---

## 🔹 mysql

Contiene:

* Usuarios
* Hashes
* Permisos
* Roles

Tabla crítica:

```
mysql.user
```

⚠️ Desde perspectiva ofensiva:
Si se logra leer esta tabla → posible extracción de hashes.

---

## 🔹 information_schema

Contiene metadata ANSI/ISO:

* Tablas
* Columnas
* Índices
* Permisos

Es clave para:

* Enumeración silenciosa
* Reconstrucción de estructura de base
* Preparación para SQL Injection

---

## 🔹 performance_schema

* Métricas internas
* Locks
* Estadísticas

Útil para:

* Análisis forense
* Detección de actividad

---

## 🔹 sys

Vista simplificada y amigable del performance_schema.

Ejemplo:

```sql
select host, unique_users from host_summary;
```

Permite identificar:

* Desde qué hosts se conectan usuarios
* Número de usuarios únicos

Esto puede revelar:

* Movimiento lateral
* Clientes activos
* Accesos remotos

---

# 7️⃣ Enumeración Estratégica Post-Login

Una vez autenticados, pasos recomendados:

1. Identificar versión exacta:

   ```sql
   select version();
   ```

2. Identificar privilegios actuales:

   ```sql
   show grants;
   ```

3. Listar usuarios:

   ```sql
   select user, host from mysql.user;
   ```

4. Buscar bases personalizadas:

   ```sql
   show databases;
   ```

5. Enumerar tablas sensibles:

   ```sql
   show tables;
   ```

---

# 8️⃣ Consideraciones de Seguridad

Durante footprinting MySQL debemos evaluar:

* ¿Está expuesto públicamente?
* ¿Permite autenticación remota de root?
* ¿Qué plugin de auth usa?
* ¿Se usa SSL?
* ¿Permite LOAD DATA LOCAL?
* ¿Existen usuarios con host '%'?

---

# 9️⃣ Errores Comunes en Pentesting MySQL

* Confiar en scripts NSE sin validar
* No revisar plugin de autenticación
* Ignorar capacidades flags
* No revisar privilegios actuales
* No analizar configuración del servidor

---

Para consolidar conocimientos:

* Instalar MySQL en una VM
* Configurar usuarios con distintos hosts
* Cambiar plugins de autenticación
* Activar y desactivar SSL
* Practicar hardening

---



---

# Preeguntas


#### Enumerar el servidor MySQL y determinar la versión en uso. (Formato: MySQL XXXX)


#### Durante nuestra prueba de penetración, encontramos credenciales débiles "robin:robin". Deberíamos probarlas con el servidor MySQL. ¿Cuál es la dirección de correo electrónico del cliente "Otto Lang"?
