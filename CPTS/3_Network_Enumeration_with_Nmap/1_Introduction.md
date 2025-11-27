# 🔍 Introducción a Nmap

*Módulo: Network Enumeration with Nmap (HTB)*

## 📌 ¿Qué es Nmap?

**Nmap (Network Mapper)** es una herramienta de análisis de red y auditoría de seguridad **open‑source**, escrita en **C, C++, Python y Lua**. Está diseñada para:

* Escanear redes utilizando **paquetes raw**.
* Identificar **hosts activos**.
* Enumerar **servicios y aplicaciones**, incluyendo su **nombre y versión**.
* Detectar **sistemas operativos** y sus versiones.
* Analizar la presencia y configuración de **firewalls, IDS e IPS**.

Es una herramienta fundamental en cualquier proceso de enumeración activa.

---

## 📌 Casos de Uso

Nmap es una de las herramientas más utilizadas por administradores de red y profesionales de seguridad. Se usa para:

* 🔐 Auditar la seguridad de redes.
* 🛡️ Simular pruebas de penetración.
* 🔥 Verificar la configuración de firewalls e IDS.
* 🌐 Mapear redes.
* 📡 Analizar respuestas de hosts.
* 🕳️ Identificar puertos abiertos.
* 🩻 Realizar evaluaciones iniciales de vulnerabilidades.

---

## 📌 Arquitectura de Nmap

Nmap incluye múltiples tipos de escaneos, cada uno útil para obtener diferentes tipos de información.

Las categorías básicas son:

1. **Host Discovery** – Identifica equipos encendidos.
2. **Port Scanning** – Identifica puertos abiertos, cerrados o filtrados.
3. **Service Enumeration & Detection** – Detecta servicios y versiones.
4. **OS Detection** – Reconoce el sistema operativo del host.
5. **Nmap Scripting Engine (NSE)** – Ejecuta scripts para interactuar con servicios.

---

## 📌 Sintaxis Básica

La sintaxis de Nmap es simple:

```
nmap <scan types> <options> <target>
```

Ejemplo:

```
nmap -sS -sV -O 10.10.10.10
```

---

## 📌 Técnicas de Escaneo en Nmap

Nmap ofrece una amplia variedad de técnicas, cada una enviando distintos tipos de paquetes.

Comando para ver todas:

```
nmap --help
```

### Principales técnicas (según el módulo):

* **-sS / -sT / -sA / -sW / -sM** → Escaneos TCP SYN, Connect(), ACK, Window, Maimon
* **-sU** → Escaneo UDP
* **-sN / -sF / -sX** → Escaneos TCP Null, FIN y Xmas
* **--scanflags <flags>** → Flags TCP personalizados
* **-sI** → Idle scan (usando zombie)
* **-sY / -sZ** → Escaneos SCTP INIT/COOKIE-ECHO
* **-sO** → Escaneo de protocolos IP
* **-b <host>** → FTP bounce scan

---

## 📌 El Escaneo TCP SYN (-sS)

Es uno de los métodos más utilizados y forma parte de la configuración por defecto de Nmap.

Características:

* Muy rápido → puede escanear **miles de puertos por segundo**.
* No completa el **three‑way handshake** → escaneo semiabierto.
* Menos ruidoso que un Connect() scan.

### Flujo de respuesta:

* 🔓 **SYN‑ACK recibido** → puerto **abierto**.
* ❌ **RST recibido** → puerto **cerrado**.
* 🕵️ **Sin respuesta** → puerto **filtrado** (probablemente un firewall descartó el paquete).

---

## 📌 Ejemplo Real del Módulo

Ejecutamos un SYN scan sobre localhost:

```
sudo nmap -sS localhost
```

Salida:

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-11 22:50 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000010s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5432/tcp open  postgresql
5901/tcp open  vnc-1

Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds
```

### Interpretación:

* Se omitieron 996 puertos cerrados («Not shown»).
* Se listan **4 puertos abiertos**:

  * **22/tcp** → ssh
  * **80/tcp** → http
  * **5432/tcp** → postgresql
  * **5901/tcp** → vnc-1

Cada línea contiene:

1. **Número de puerto**
2. **Estado**
3. **Servicio detectado**

---

Este lienzo cubre íntegramente la parte "Introduction to Nmap" del módulo que pasaste. Cuando quieras, enviame la siguiente sección y continúo con el próximo lienzo.
