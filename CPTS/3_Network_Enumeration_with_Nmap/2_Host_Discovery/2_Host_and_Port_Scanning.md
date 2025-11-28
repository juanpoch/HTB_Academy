# 🚀 Host and Port Scanning con Nmap

*Módulo: Network Enumeration with Nmap (HTB)*

Comprender **cómo Nmap realiza los escaneos**, cómo obtiene la información y cómo interpretar correctamente los resultados es esencial para cualquier pentester.

Después de confirmar que el objetivo está vivo, queremos obtener un **“mapa” más preciso del sistema**. La información clave que buscamos es:

* Puertos abiertos y sus servicios
* Versiones de los servicios
* Información adicional expuesta por los servicios
* Sistema operativo

---

## 📌 Estados posibles de un puerto en Nmap

Nmap puede clasificar cada puerto en **uno de 6 estados**:

| Estado              | Descripción                                                                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **open**            | Hay una conexión establecida al puerto. Puede ser una conexión TCP, un datagrama UDP o una asociación SCTP.                                  |
| **closed**          | El puerto está cerrado. En TCP esto se ve porque la respuesta contiene un flag **RST**. Aun así, nos sirve para saber que el host está vivo. |
| **filtered**        | Nmap no puede determinar si el puerto está open o closed porque no recibe respuesta o recibe un error (por ejemplo, firewall).               |
| **unfiltered**      | Solo aparece en escaneos **TCP ACK**. El puerto es accesible, pero Nmap no puede determinar si está open o closed.                           |
| **open|filtered**   | Sin respuesta. Puede estar abierto pero filtrado por un firewall o filtro de paquetes. Muy común en UDP.                                     |
| **closed|filtered** | Solo aparece en **IP ID idle scans**. Nmap no pudo decir si el puerto está cerrado o filtrado por un firewall.                               |

---

## 🔥 Descubriendo puertos TCP abiertos

Por defecto, Nmap:

* Escanea los **1000 puertos TCP más comunes**.
* Si se ejecuta como **root**, usa **SYN scan (-sS)**.
* Si NO es root, usa **Connect scan (-sT)**.

Podemos elegir los puertos con:

* Puertos específicos: `-p 22,25,80,139,445`
* Rango: `-p 22-445`
* Top ports: `--top-ports=10`
* Todos los puertos: `-p-`
* Escaneo rápido de 100 puertos más comunes: `-F`

---

## 🧪 Escaneo de los Top 10 puertos TCP

```bash
sudo nmap 10.129.2.28 --top-ports=10
```

Salida (resumida):

```text
Host is up (0.021s latency).

PORT     STATE    SERVICE
21/tcp   closed   ftp
22/tcp   open     ssh
23/tcp   closed   telnet
25/tcp   open     smtp
80/tcp   open     http
110/tcp  open     pop3
139/tcp  filtered netbios-ssn
443/tcp  closed   https
445/tcp  filtered microsoft-ds
3389/tcp closed   ms-wbt-server
```

### Opciones usadas

| Opción           | Descripción                                                               |
| ---------------- | ------------------------------------------------------------------------- |
| `10.129.2.28`    | Objetivo a escanear.                                                      |
| `--top-ports=10` | Escanea los 10 puertos TCP más frecuentes según la base de datos de Nmap. |

Vemos que solo se escanean los top 10 puertos TCP, y Nmap nos muestra el **estado** de cada uno.

---

## 📡 Analizando los paquetes con `--packet-trace` (SYN scan)

Para entender bien el comportamiento del SYN scan, desactivamos:

* Ping ICMP: `-Pn`
* Resolución DNS: `-n`
* ARP ping: `--disable-arp-ping`

Y trazamos los paquetes:

```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```

Salida relevante:

```text
SENT (0.0429s) TCP 10.10.14.2:63090 > 10.129.2.28:21 S ...
RCVD (0.0573s) TCP 10.129.2.28:21 > 10.10.14.2:63090 RA ...
```

### Interpretación de la petición (Request)

* `SENT (0.0429s)` → Nmap envía un paquete al objetivo.
* `TCP` → Protocolo usado.
* `10.10.14.2:63090 > 10.129.2.28:21` → IP/puerto origen → IP/puerto destino.
* `S` → Flag **SYN** del paquete enviado.
* Resto (`ttl`, `id`, `iplen`, `seq`, `win`, `mss`) → Parámetros de cabecera TCP/IP.

### Interpretación de la respuesta (Response)

* `RCVD (0.0573s)` → Nmap recibe un paquete del objetivo.
* `10.129.2.28:21 > 10.10.14.2:63090` → IP/puerto origen → IP/puerto destino.
* `RA` → Flags **RST** + **ACK** → indica que el puerto **está cerrado**.

Nmap traduce esto a:

```text
PORT   STATE  SERVICE
21/tcp closed ftp
```

---

## 🔐 Connect Scan (-sT)

El [**TCP Connect Scan (-sT)**](https://nmap.org/book/scan-methods-connect-scan.html) utiliza el **three-way handshake completo** para determinar el estado del puerto:

* Enviar SYN
* Recibir SYN-ACK → puerto **open**
* Recibir RST → puerto **closed**

### Características

✅ **Ventajas:**

* Muy **preciso** (se completa la conexión).
* Útil cuando la prioridad es el mapeo exacto de puertos.
* Interactúa como un cliente legítimo → menos probabilidad de romper servicios.

❌ **Desventajas:**

* Es de los métodos **menos sigilosos**.
* Genera logs en casi todos los sistemas.
* Más lento que SYN scan, porque completa conexiones.

Es especialmente útil cuando:

* El host tiene un **firewall personal** que filtra conexiones entrantes pero permite salientes: el Connect scan puede aprovecharlo y determinar el estado de los puertos.

---

## 🌐 Ejemplo: Connect Scan en el puerto 443

```bash
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

Salida relevante:

```text
CONN (0.0385s) TCP localhost > 10.129.2.28:443 => Operation now in progress
CONN (0.0396s) TCP localhost > 10.129.2.28:443 => Connected

PORT    STATE SERVICE REASON
443/tcp open  https   syn-ack
```

* `CONN ... Connected` → Nmap completó el three-way handshake.
* `STATE: open`, `REASON: syn-ack` → el puerto 443/tcp está **abierto (https)**.

---

## 🚧 Puertos filtrados (filtered)

Cuando un puerto se muestra como **filtered**, suele haber un **firewall** o filtro manejando el tráfico.

Dos posibilidades típicas:

1. **DROP** → descarta silenciosamente los paquetes (sin respuesta).
2. **REJECT** → responde con mensaje de error (por ejemplo, ICMP Port Unreachable).

Nmap, por defecto, reintenta varias veces (`--max-retries=10`). Esto hace que un puerto filtrado pueda tardar mucho más en ser clasificado.

---

### 🔸 Ejemplo: firewall DROPPING (puerto 139)

```bash
sudo nmap 10.129.2.28 -p 139 --packet-trace -n --disable-arp-ping -Pn
```

Salida relevante:

```text
SENT (...) TCP ...:60277 > 10.129.2.28:139 S ...
SENT (...) TCP ...:60278 > 10.129.2.28:139 S ...
...
PORT    STATE    SERVICE
139/tcp filtered netbios-ssn
```

* Nmap envía varios SYN.
* No recibe respuesta → considera el puerto **filtered**.
* El scan tarda más (~2.06s) comparado con un puerto claramente abierto/cerrado (~0.05s).

---

### 🔸 Ejemplo: firewall REJECTING (puerto 445)

```bash
sudo nmap 10.129.2.28 -p 445 --packet-trace -n --disable-arp-ping -Pn
```

Salida relevante:

```text
SENT (...) TCP ...:52472 > 10.129.2.28:445 S ...
RCVD (...) ICMP [10.129.2.28 > 10.129.2.28 Port 445 unreachable (type=3/code=3) ]
...
PORT    STATE    SERVICE
445/tcp filtered microsoft-ds
```

* Recibimos un **ICMP type=3 code=3 (Port unreachable)**.
* Sabemos que el host está vivo, así que podemos asumir que **el firewall está rechazando el acceso al puerto 445**.
* Es un puerto a tener en cuenta para análisis posterior (SMB).

---

## 🔵 Discovering Open UDP Ports (-sU)

Los admins a veces configuran bien los filtros TCP pero **se olvidan de UDP**.

Particularidades de UDP:

* Es **stateless** → no hay three-way handshake.
* No hay ACK por defecto.
* Los timeouts son más largos → escaneos **más lentos**.
* Muy común ver puertos `open|filtered`.

### Ejemplo: UDP Scan rápido

```bash
sudo nmap 10.129.2.28 -F -sU
```

Salida relevante:

```text
Not shown: 95 closed ports
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
137/udp  open          netbios-ns
138/udp  open|filtered netbios-dgm
631/udp  open|filtered ipp
5353/udp open          zeroconf
```

* Muchos puertos aparecen como **open|filtered**.
* Algunos como **open** si la aplicación responde.

---

## 🔬 Trazando UDP con `--packet-trace` y `--reason`

### UDP abierto (puerto 137)

```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 137 --reason
```

Salida relevante:

```text
SENT (...) UDP 10.10.14.2:55478 > 10.129.2.28:137 ...
RCVD (...) UDP 10.129.2.28:137 > 10.10.14.2:55478 ...
PORT    STATE SERVICE    REASON
137/udp open  netbios-ns udp-response ttl 64
```

* Enviamos un datagrama UDP.
* Recibimos **respuesta UDP**.
* Nmap marca el puerto como **open**.

---

### UDP cerrado (ICMP port unreachable, puerto 100)

```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 100 --reason
```

Salida relevante:

```text
RCVD (...) ICMP [...] Port unreachable (type=3/code=3)
PORT    STATE  SERVICE REASON
100/udp closed unknown port-unreach ttl 64
```

* ICMP type=3 code=3 → **port unreachable**.
* Nmap marca el puerto como **closed**.

---

### UDP open|filtered (sin respuesta, puerto 138)

```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 138 --reason
```

Salida relevante:

```text
SENT (...) UDP ...:52341 > 10.129.2.28:138 ...
SENT (...) UDP ...:52342 > 10.129.2.28:138 ...
PORT    STATE         SERVICE     REASON
138/udp open|filtered netbios-dgm no-response
```

* Se envían varios datagramas UDP.
* No hay respuesta ni ICMP de error.
* Nmap no puede saber si está **abierto o filtrado** → `open|filtered`.

---

## 🧭 Version Scan (-sV)

El flag `-sV` pide a Nmap que:

* Identifique el **servicio** (ej: Samba, Apache, OpenSSH).
* Identifique la **versión**.
* Use sondas (probes) para hablar con el servicio y sacar más información.

### Ejemplo: versión en el puerto 445 (SMB)

```bash
sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason -sV
```

Salida relevante:

```text
PORT    STATE SERVICE     REASON         VERSION
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: Ubuntu
```

Nmap concluye que:

* Puerto 445/tcp → **netbios-ssn**
* Servicio: **Samba smbd 3.X - 4.X**
* Workgroup: **WORKGROUP**
* Host parece ser: **Ubuntu**

### Opciones usadas

| Opción               | Descripción                                      |
| -------------------- | ------------------------------------------------ |
| `-sV`                | Service/version scan.                            |
| `--reason`           | Muestra el motivo por el que asigna ese estado.  |
| `--packet-trace`     | Muestra todos los paquetes enviados y recibidos. |
| `-Pn`                | No hace ping previo (ICMP deshabilitado).        |
| `-n`                 | Sin resolución DNS.                              |
| `--disable-arp-ping` | Sin ARP ping.                                    |
| `-p 445`             | Solo el puerto 445.                              |

---

## 📚 Más información

Más detalles sobre técnicas de escaneo de puertos:
👉 [https://nmap.org/book/man-port-scanning-techniques.html](https://nmap.org/book/man-port-scanning-techniques.html)



---

#### Preguntas

#### Encuentra todos los puertos TCP en tu objetivo. Indica el número total de puertos TCP encontrados como respuesta.

Realizamos un escaneo TCP SYN y descubrimos 7 puertos abiertos:

<img width="1131" height="730" alt="image" src="https://github.com/user-attachments/assets/9e8b3ef6-63ac-4ee7-807e-a03258c886cb" />


#### Enumere el nombre de host de su objetivo y envíelo como respuesta. (distingue entre mayúsculas y minúsculas)
