# 🗄️ MSSQL – Microsoft SQL Server


---

# 1️⃣ ¿Qué es MSSQL?

**Microsoft SQL Server ([MSSQL](https://www.microsoft.com/en-us/sql-server/sql-server-2019))** es el sistema de gestión de bases de datos relacional desarrollado por Microsoft.

A diferencia de MySQL:

* Es **software propietario (closed source)**
* Está fuertemente integrado con el ecosistema Windows
* Tiene integración nativa con **Active Directory**
* Es muy utilizado en entornos empresariales grandes

Aunque hoy existen versiones para Linux y MacOS, lo más común es encontrarlo en:

👉 Servidores Windows
👉 Entornos corporativos con Active Directory
👉 Aplicaciones .NET

---

# 2️⃣ Arquitectura General

MSSQL funciona bajo el modelo cliente-servidor.

* El servidor escucha por defecto en:

```
TCP/1433
```

* Puede usar también:

  * Named Pipes
  * DAC (Dedicated Admin Connection)
  * TLS

Internamente utiliza:

* Motor SQL Database Engine
* T-SQL (Transact-SQL)
* System Databases

---

# 3️⃣ Clientes MSSQL

Uno de los puntos clave es entender que el cliente NO tiene que estar en el servidor.

## 🖥️ SQL Server Management Studio (SSMS)

Es la herramienta gráfica más común.

Puede:

* Administrar bases
* Crear usuarios
* Ejecutar queries
* Configurar seguridad
* Programar jobs

⚠️ Como pentesters esto es interesante porque:

> Podríamos encontrar una máquina con SSMS instalado y credenciales guardadas.

[SQL Server Management Studio SSMS](https://learn.microsoft.com/en-us/ssms/install/install?view=sql-server-ver15)


<img width="987" height="721" alt="image" src="https://github.com/user-attachments/assets/230e0324-873e-4c22-ada2-ce464a5f1c97" />


---

## 🧰 Otros clientes

* [mssql-cli](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver15&tabs=go%2Cwindows-support&pivots=cs1-bash)
* [SQL Server PowerShell](https://learn.microsoft.com/en-us/powershell/sql-server/sql-server-powershell?view=sqlserver-ps&viewFallbackFrom=sql-server-ver15)
* [HeidiSQL](https://www.heidisql.com/)
* [SQLPro](https://www.macsqlclient.com/)
* [Impacket mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)

En pentesting, el más importante suele ser:

👉 `impacket-mssqlclient.py`

---

## 🔎 Localizar el cliente en Kali

```bash
CyberWolfSec@htb[/htb]$ locate mssqlclient

/usr/bin/impacket-mssqlclient
/usr/share/doc/python3-impacket/examples/mssqlclient.py
```

---

# 4️⃣ Bases de Datos del Sistema

MSSQL cuenta con bases de datos de sistema predeterminadas que nos ayudan a comprender la estructura de todas las bases de datos que pueden estar alojadas en un servidor de destino:

| Base del Sistema | Descripción                                                                 | Notas Importantes para Pentesting |
|------------------|------------------------------------------------------------------------------|------------------------------------|
| **master**       | Almacena toda la información del sistema para la instancia de SQL Server: configuración global, logins, endpoints y metadatos críticos. | Base más sensible. Permite enumerar usuarios, roles y configuraciones del servidor. |
| **model**        | Base plantilla utilizada como estructura para cada nueva base de datos creada. Cualquier cambio aquí se hereda en nuevas bases. | Puede usarse para persistencia si un atacante logra modificarla. |
| **msdb**         | Utilizada por SQL Server Agent para almacenar trabajos programados (jobs), alertas y tareas automatizadas. | Jobs mal configurados pueden permitir ejecución de comandos o escalada. |
| **tempdb**       | Almacena objetos temporales como tablas temporales, resultados intermedios y datos de sesión. Se recrea al reiniciar el servidor. | No persiste datos tras reinicio, pero puede revelar actividad en curso. |
| **resource**     | Base de datos de solo lectura que contiene objetos internos del sistema incluidos con SQL Server. | No es modificable, pero es clave para el funcionamiento interno del motor. |


[Fuente](https://learn.microsoft.com/en-us/sql/relational-databases/databases/system-databases?view=sql-server-ver15)  


---

# 🔐 MSSQL – Autenticación, Configuración por Defecto y Riesgos 


---

# 1️⃣ ¿Cómo funciona la autenticación en MSSQL?

MSSQL puede operar en dos modos principales de autenticación:

* **Windows Authentication**
* **SQL Server Authentication**

También puede funcionar en modo mixto (permitiendo ambos).

---

# 2️⃣ 🔐 Windows Authentication (Integración con el Sistema Operativo)

Este es el modo más común en entornos corporativos.

## 🧠 ¿Qué significa realmente?

Cuando un usuario intenta conectarse a MSSQL usando Windows Authentication:

1. No envía usuario/contraseña directamente a MSSQL.
2. El sistema operativo Windows valida la identidad.
3. La validación se hace contra:

   * La base local SAM (si es cuenta local)
   * El Domain Controller (si es cuenta de dominio)
4. MSSQL confía en esa validación.

Es decir:

> MSSQL delega la autenticación al sistema operativo.


<img width="486" height="529" alt="image" src="https://github.com/user-attachments/assets/5239775e-50e6-4753-91a0-8be82a74de9a" />


---

## 🔎 ¿Qué es SAM?

SAM (Security Account Manager) es la base de datos local de usuarios de Windows.

Contiene:

* Usuarios locales
* Hashes de contraseñas
* Información de grupos

Si el servidor pertenece a un dominio, la autenticación normalmente se valida contra:

👉 Active Directory

---

## 🏢 Integración con Active Directory

En entornos empresariales:

* Usuarios inician sesión en el dominio
* Active Directory gestiona permisos
* MSSQL puede permitir acceso a grupos del dominio

Ejemplo:

Un grupo de AD llamado:

```
SQL_Admins
```

Puede tener privilegios dentro de MSSQL.

⚠️ Implicación ofensiva:

Si comprometemos una cuenta de dominio con privilegios sobre MSSQL:

* Podemos acceder a la base
* Enumerar datos
* Ejecutar consultas
* Potencialmente escalar privilegios
* Hacer movimiento lateral

---

# 3️⃣ 🔑 SQL Server Authentication

Este modo usa credenciales propias de MSSQL.

Ejemplo clásico:

```
Usuario: sa
Password: <contraseña>
```

`sa` es el usuario administrador interno de MSSQL.

---

## ⚠️ Riesgos comunes

* `sa` con password débil
* `sa` habilitado cuando no debería
* Reutilización de credenciales
* Passwords por defecto

A diferencia de Windows Authentication:

👉 Aquí sí se envía usuario/contraseña al motor SQL.

---

# 4️⃣ Modo Mixto (Mixed Mode)

Muchos servidores están configurados en modo mixto:

* Permiten Windows Authentication
* Permiten SQL Authentication

Esto amplía superficie de ataque.

---

# 5️⃣ Configuración por Defecto al Instalar MSSQL

Cuando un administrador instala MSSQL y lo hace accesible en red:

## 🔧 Servicio del sistema

El servicio suele ejecutarse como:

```
NT SERVICE\MSSQLSERVER
```

Esto es una cuenta de servicio virtual administrada por Windows.

No es una cuenta humana.

---

## 🌐 Puerto por defecto

MSSQL escucha en:

```
TCP 1433
```

Puede configurarse otro puerto, pero 1433 es el estándar.

---

## 🔓 Cifrado por defecto

Por defecto:

* No siempre se fuerza cifrado
* Puede aceptar conexiones sin TLS

Esto significa que:

* Credenciales pueden viajar en texto claro
* Puede ser vulnerable a sniffing

---

# 6️⃣ Named Pipes

MSSQL puede comunicarse usando:

* TCP/IP
* Named Pipes

Named Pipes es un mecanismo de comunicación interna de Windows.

Ejemplo:

```
\\SQL-01\pipe\sql\query
```

⚠️ Desde perspectiva ofensiva:

* Puede facilitar movimiento lateral
* Puede ser explotado si hay permisos indebidos

[Named pipes](https://learn.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)

---

# 7️⃣ Configuraciones Peligrosas

En un engagement debemos pensar como administradores.

Un admin puede cometer errores por:

* Presión laboral
* Configuraciones rápidas
* Falta de hardening

Algunas configuraciones peligrosas incluyen:

---

## 🔓 1. Conexiones sin cifrado

Si no se fuerza TLS:

* Credenciales pueden ser interceptadas
* Tráfico puede ser inspeccionado

---

## 📜 2. Certificados autofirmados

Si se usa TLS con certificado self-signed:

* Puede ser vulnerable a spoofing
* Facilita ataques MITM

---

## 🧵 3. Named Pipes habilitado

Puede ampliar superficie de ataque interna.

---

## 🔑 4. Cuenta `sa` activa

Especialmente peligrosa si:

* Tiene password débil
* Es reutilizada en otros sistemas

---

## 💣 5. xp_cmdshell habilitado

`xp_cmdshell` permite ejecutar comandos del sistema operativo desde SQL.

Ejemplo:

```sql
EXEC xp_cmdshell 'whoami';
```

Si está habilitado y tenemos privilegios adecuados:

👉 Podemos ejecutar comandos en el servidor Windows.

Eso convierte a MSSQL en punto de pivot o escalada.

---

# 🛰️ MSSQL – Footprinting y Enumeración



---

# 1️⃣ ¿Qué significa “Footprinting” en MSSQL?

Footprinting es el proceso de:

* Identificar que el servicio existe
* Detectar versión exacta
* Descubrir nombre del servidor
* Detectar instancia
* Saber si usa cifrado
* Saber si usa Named Pipes
* Identificar integración con dominio
* Detectar posibles configuraciones débiles

En MSSQL esto es especialmente importante porque:

👉 Puede estar integrado con Active Directory
👉 Puede permitir ejecución de comandos del sistema
👉 Puede facilitar movimiento lateral

---

# 2️⃣ Puerto por defecto de MSSQL

MSSQL escucha normalmente en:

```
TCP 1433
```

Ese es nuestro primer indicador.

Si vemos 1433 abierto → probablemente hay una instancia de SQL Server.

---

# 3️⃣ Enumeración con Nmap

Comando utilizado:

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

---

## 🧠 ¿Qué estamos haciendo realmente?

### `-p 1433`

Escaneamos únicamente el puerto MSSQL.

### `-sV`

Intentamos detectar versión exacta del servicio.

### `--script ms-sql-*`

Ejecutamos scripts específicos para MSSQL.

Estos scripts intentan:

* Obtener versión
* Detectar si `sa` tiene password vacío
* Detectar si xp_cmdshell está habilitado
* Obtener información NTLM
* Detectar Named Pipes
* Intentar listar bases

---

# 4️⃣ Análisis de la Salida (Paso a Paso)

Salida:

```text
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
```

## 🔎 Qué significa esto

* El puerto está abierto
* Es MSSQL
* Versión: SQL Server 2019
* Build: 15.00.2000.00
* RTM = Release To Manufacturing (sin service pack)

👉 Esto ya nos permite buscar vulnerabilidades específicas por versión.

---

## ms-sql-ntlm-info

```text
|   Target_Name: SQL-01
|   NetBIOS_Domain_Name: SQL-01
|   NetBIOS_Computer_Name: SQL-01
|   DNS_Domain_Name: SQL-01
|   DNS_Computer_Name: SQL-01
|_  Product_Version: 10.0.17763
```

### 🔍 Qué aprendemos

* Hostname real: **SQL-01**
* No parece estar en dominio (NetBIOS_Domain_Name igual al hostname)
* Product_Version 10.0.17763 → Windows Server 2019

👉 Ahora sabemos:

* Sistema operativo
* Nombre real del servidor

Esto es información clave para movimiento lateral.

---

## ms-sql-info

```text
Instance name: MSSQLSERVER
Named pipe: \\10.129.201.248\pipe\sql\query
Clustered: false
```

### 🔎 Instance name

MSSQL puede tener múltiples instancias.

`MSSQLSERVER` = instancia por defecto.

---

### 🔎 Named Pipe

```
\\10.129.201.248\pipe\sql\query
```

Esto indica que el servicio permite comunicación vía Named Pipes.

👉 Esto puede facilitar ataques internos o movimiento lateral.

---

### 🔎 Clustered: false

No está en cluster.

Menos complejidad, menos redundancia.

---

# 5️⃣ Footprinting con Metasploit

Comando:

```bash
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```

Salida:

```text
[+] 10.129.201.248:       -    ServerName      = SQL-01
[+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
[+] 10.129.201.248:       -    IsClustered     = No
[+] 10.129.201.248:       -    Version         = 15.0.2000.5
[+] 10.129.201.248:       -    tcp             = 1433
[+] 10.129.201.248:       -    np              = \\SQL-01\pipe\sql\query
```

## 🧠 Qué confirma

Metasploit valida:

* Nombre del servidor
* Versión
* Puerto
* Named pipes

Es una segunda fuente de confirmación.

---

# 6️⃣ Conexión Real con Impacket

Comando:

```bash
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

Salida:

```text
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-01): Line 1: Changed database context to 'master'.
[*] INFO(SQL-01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
```

## 🔐 ¿Qué significa esto?

* El servidor exige cifrado
* Se negocia TLS automáticamente
* Nos autenticamos con Windows Authentication

👉 Esto demuestra integración con el sistema operativo.

---

# 7️⃣ Enumeración Interna

Comando:

```sql
SQL> select name from sys.databases
```

Salida:

```text
master
tempdb
model
msdb
Transactions
```

## 🧠 Qué significa

Las primeras cuatro son bases del sistema.

`Transactions` es una base creada por la organización.

👉 Aquí es donde suele haber datos reales.

---

# 8️⃣ Qué es T-SQL

T-SQL (Transact-SQL) es una extensión de SQL que incluye:

* Variables
* Bucles
* Condicionales
* Procedimientos almacenados
* Ejecución de comandos del sistema (si xp_cmdshell está habilitado)

Ejemplo:

```sql
SELECT @@version;
```

---

# 9️⃣ Riesgos Ofensivos Reales

Desde MSSQL podemos:

* Enumerar usuarios
* Detectar roles
* Intentar escalar a sysadmin
* Ejecutar xp_cmdshell
* Leer archivos
* Escribir archivos
* Pivotear dentro del dominio

MSSQL en Windows puede convertirse en un punto crítico de compromiso.

---

# 🔟 Resumen Estratégico

Durante el footprinting aprendimos:

* Versión exacta
* Nombre del servidor
* Sistema operativo
* Puerto activo
* Named pipes habilitado
* No clusterizado
* Cifrado activo

Todo esto reduce incertidumbre.

Footprinting no es solo "ver que está abierto".

Es entender:

👉 Cómo está configurado
👉 Cómo se autentica
👉 Cómo podría ser abusado

---

# 🎯 Conclusión Final

MSSQL es mucho más que una base de datos.

En entornos Windows empresariales:

* Está ligado a Active Directory
* Puede ejecutar comandos del sistema
* Puede permitir movimiento lateral
* Puede almacenar información crítica

Entender el footprinting correctamente es el primer paso para evaluar el verdadero riesgo del servicio.


---

## Preguntas


#### Enumere el destino utilizando los conceptos enseñados en esta sección. Indique el nombre de host del servidor MSSQL.



#### Conéctese a la instancia MSSQL que se ejecuta en el destino usando la cuenta (backdoor:Password1) y luego enumere la base de datos no predeterminada presente en el servidor.

`Hint`: Recuerde que el sistema operativo de destino en el que nos estamos autenticando es Windows.
