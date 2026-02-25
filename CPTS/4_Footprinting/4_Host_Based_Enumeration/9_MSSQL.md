# 🗄️ MSSQL – Microsoft SQL Server


---

# 1️⃣ ¿Qué es MSSQL?

**Microsoft SQL Server (MSSQL)** es el sistema de gestión de bases de datos relacional desarrollado por Microsoft.

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

---

## 🧰 Otros clientes

* mssql-cli
* SQL Server PowerShell
* HeidiSQL
* SQLPro
* Impacket mssqlclient.py

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

MSSQL incluye bases críticas por defecto.

| Base     | Función                                        |
| -------- | ---------------------------------------------- |
| master   | Información del sistema y configuración global |
| model    | Plantilla para nuevas bases                    |
| msdb     | Jobs y tareas programadas                      |
| tempdb   | Objetos temporales                             |
| resource | Objetos internos del sistema                   |

---

# 5️⃣ Autenticación en MSSQL

Existen dos modos principales:

## 🔐 Windows Authentication

* Utiliza credenciales del sistema operativo
* Puede usar Active Directory
* Ideal para entornos corporativos

Flujo:

1. Usuario se autentica en Windows
2. Windows valida contra SAM o Domain Controller
3. MSSQL confía en esa autenticación

⚠️ Si comprometemos una cuenta de dominio → podríamos acceder a MSSQL.

---

## 🔑 SQL Authentication

* Usuario y contraseña propios de MSSQL
* Ejemplo clásico: `sa`

⚠️ Muchas veces:

* `sa` tiene password débil
* `sa` no fue deshabilitado

---

# 6️⃣ Configuración por Defecto

Cuando MSSQL se instala y se expone en red:

* Servicio corre como:

```
NT SERVICE\MSSQLSERVER
```

* Escucha en 1433
* Por defecto puede no forzar cifrado

---

# 7️⃣ Configuraciones Peligrosas

Como pentesters debemos buscar:

* Conexiones sin cifrado
* Certificados autofirmados
* Named Pipes habilitados
* Cuenta `sa` activa
* xp_cmdshell habilitado

---

# 8️⃣ Footprinting con Nmap

Escaneo completo con scripts específicos:

```bash
CyberWolfSec@htb[/htb]$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

Salida:

```text
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: SQL-01
|   NetBIOS_Domain_Name: SQL-01
|   NetBIOS_Computer_Name: SQL-01
|   DNS_Domain_Name: SQL-01
|   DNS_Computer_Name: SQL-01
|_  Product_Version: 10.0.17763

Host script results:
| ms-sql-dac:
|_  Instance: MSSQLSERVER; DAC port: 1434 (connection failed)
| ms-sql-info:
|   Windows server name: SQL-01
|   10.129.201.248\MSSQLSERVER:
|     Instance name: MSSQLSERVER
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 1433
|     Named pipe: \\10.129.201.248\pipe\sql\query
|_    Clustered: false
```

### 🔎 Qué aprendimos

* Hostname: SQL-01
* Versión exacta
* No tiene service pack
* Named pipes habilitado
* No es cluster

Todo esto es información de superficie de ataque.

---

# 9️⃣ Footprinting con Metasploit

```bash
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```

Salida:

```text
[*] 10.129.201.248:       - SQL Server information for 10.129.201.248:
[+] 10.129.201.248:       -    ServerName      = SQL-01
[+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
[+] 10.129.201.248:       -    IsClustered     = No
[+] 10.129.201.248:       -    Version         = 15.0.2000.5
[+] 10.129.201.248:       -    tcp             = 1433
[+] 10.129.201.248:       -    np              = \\SQL-01\pipe\sql\query
```

---

# 🔟 Conexión con Impacket

```bash
CyberWolfSec@htb[/htb]$ python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
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
[!] Press help for extra shell commands
```

Listar bases:

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

---

# 1️⃣1️⃣ T-SQL (Transact-SQL)

MSSQL usa T-SQL, que es una extensión de SQL estándar.

Permite:

* Procedimientos almacenados
* Variables
* Control de flujo
* Ejecución de comandos del sistema (si está habilitado xp_cmdshell)

---

# 1️⃣2️⃣ Riesgos Ofensivos Clásicos

* `xp_cmdshell` habilitado
* Permisos sysadmin
* Uso de cuenta de dominio
* Acceso a archivos
* Movimiento lateral

---

# 1️⃣3️⃣ Conclusión

MSSQL no es solo una base de datos.

En entornos Windows:

👉 Está integrado con el dominio
👉 Puede ejecutar comandos del sistema
👉 Puede convertirse en punto de pivot

Como pentesters debemos:

* Enumerar versión
* Detectar autenticación
* Ver named pipes
* Analizar permisos
* Evaluar cifrado

Entender MSSQL profundamente es clave para comprometer entornos empresariales Windows.
