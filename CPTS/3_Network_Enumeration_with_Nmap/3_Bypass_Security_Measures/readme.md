# Nmap — Firewall e IDS/IPS Evasion


---

## 🛡️ Firewalls, IDS e IPS

### 🔥 Firewalls

Un **firewall** es un mecanismo de seguridad que controla el tráfico de red entre redes (por ejemplo, Internet ↔ red interna) según reglas definidas.

* Inspecciona paquetes y decide si:

  * Los **permite**
  * Los **ignora** (los "deja caer")
  * Los **bloquea de forma explícita** (enviando respuestas de error)
* Su objetivo es **evitar conexiones no autorizadas** que puedan ser peligrosas.

---

### 👁️ IDS (Intrusion Detection System)

Un **IDS**:

* Monitorea el tráfico de red de forma **pasiva**.
* Busca patrones conocidos de ataque (signaturas, firmas, comportamientos sospechosos).
* **No bloquea** por sí mismo: **notifica al administrador** cuando detecta algo sospechoso.

### 🛡️ IPS (Intrusion Prevention System)

Un **IPS** complementa al IDS:

* Detecta posibles ataques (como un IDS).
* **Actúa automáticamente**: bloquea IPs, corta conexiones, cambia reglas, etc.
* Suele trabajar con firmas, reglas y patrones específicos (por ejemplo, detección de un escaneo de servicios).

En un pentest, un IPS puede:

* Bloquear nuestra IP.
* Hacer que el ISP sea notificado en casos extremos.

---

## 🔍 Detección de Firewalls y sus Reglas

Sabemos que, en Nmap, un puerto puede aparecer como:

* `open`
* `closed`
* `filtered`

Cuando vemos `filtered`, normalmente hay un firewall de por medio que está:

* **dejando caer** paquetes → no hay respuesta.
* o **rechazando** → devuelve mensajes ICMP o RST.

Errores ICMP típicos:

* `Net Unreachable`
* `Net Prohibited`
* `Host Unreachable`
* `Host Prohibited`
* `Port Unreachable`
* `Proto Unreachable`

---

## 🔁 Comparación: SYN Scan (-sS) vs ACK Scan (-sA)

### 🔹 SYN Scan (-sS)

Envía paquetes con flag **SYN** para intentar iniciar la conexión TCP.

Ejemplo:

```bash
sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace
```
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:56 CEST
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:22 S ttl=53 id=22412 iplen=44  seq=4092255222 win=1024 <mss 1460>
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:25 S ttl=50 id=62291 iplen=44  seq=4092255222 win=1024 <mss 1460>
SENT (0.0278s) TCP 10.10.14.2:57347 > 10.129.2.28:21 S ttl=58 id=38696 iplen=44  seq=4092255222 win=1024 <mss 1460>
RCVD (0.0329s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=40884 iplen=72 ]
RCVD (0.0341s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
RCVD (1.0386s) TCP 10.129.2.28:22 > 10.10.14.2:57347 SA ttl=64 id=0 iplen=44  seq=1153454414 win=64240 <mss 1460>
SENT (1.1366s) TCP 10.10.14.2:57348 > 10.129.2.28:25 S ttl=44 id=6796 iplen=44  seq=4092320759 win=1024 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.0053s latency).

PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
25/tcp filtered smtp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```

Resultado (resumen):

* `21/tcp` → `filtered`
* `22/tcp` → `open`
* `25/tcp` → `filtered`

### 🔹 ACK Scan (-sA)

El **ACK scan** es **más difícil de filtrar** por algunos firewalls.

* Envía un paquete TCP con **solo flag ACK**.
* Si el puerto está **open o closed**, el host debe responder con **RST**.
* No sirve para saber si el puerto está `open` o `closed`, sino si está **protegido por firewall**.

Ejemplo:

```bash
sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
```
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 14:57 CEST
SENT (0.0422s) TCP 10.10.14.2:49343 > 10.129.2.28:21 A ttl=49 id=12381 iplen=40  seq=0 win=1024
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:22 A ttl=41 id=5146 iplen=40  seq=0 win=1024
SENT (0.0423s) TCP 10.10.14.2:49343 > 10.129.2.28:25 A ttl=49 id=5800 iplen=40  seq=0 win=1024
RCVD (0.1252s) ICMP [10.129.2.28 > 10.10.14.2 Port 21 unreachable (type=3/code=3) ] IP [ttl=64 id=55628 iplen=68 ]
RCVD (0.1268s) TCP 10.129.2.28:22 > 10.10.14.2:49343 R ttl=64 id=0 iplen=40  seq=1660784500 win=0
SENT (1.3837s) TCP 10.10.14.2:49344 > 10.129.2.28:25 A ttl=59 id=21915 iplen=40  seq=0 win=1024
Nmap scan report for 10.129.2.28
Host is up (0.083s latency).

PORT   STATE      SERVICE
21/tcp filtered   ftp
22/tcp unfiltered ssh
25/tcp filtered   smtp
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```
Resultado (resumen):

* `21/tcp` → `filtered`
* `22/tcp` → `unfiltered`
* `25/tcp` → `filtered`

### 🧠 Interpretación clave

* `unfiltered` en un ACK scan → el paquete ACK llegó al host y recibió respuesta → el firewall **no está bloqueando** ese puerto.
* `filtered` → el firewall está interviniendo.

Comparando SYN vs ACK scan podemos inferir:

* Qué puertos están realmente expuestos.
* Qué puertos están solo bloqueados por firewall.

---

## 🕵️ Detección de IDS/IPS

Detectar firewalls es relativamente directo; detectar **IDS/IPS** es más complejo porque son **mecanismos de monitoreo**.

### Estrategia típica en pentesting

1. Usar uno o varios **VPS** con IPs diferentes.
2. Lanzar escaneos más agresivos desde un VPS.
3. Si esa IP queda bloqueada (no hay más acceso a la red objetivo):

   * Probablemente un **IPS** ha aplicado una medida automática.
   * Podemos continuar con **otra IP / otro VPS**.

Esto nos da información sobre:

* Presencia de IDS/IPS.
* Sensibilidad de las reglas de detección.

Conclusión: si detectamos que nos bloquean, debemos:

* Reducir agresividad.
* Hacer escaneos más lentos y sigilosos.
* Camuflar el tráfico (decoys, source port, etc.).

---

## 🎭 Decoys (-D)

Los **decoys** sirven para **ocultar el verdadero origen** de las conexiones.

Con `-D` Nmap:

* Genera varias direcciones IP (reales o aleatorias).
* Las incluye en los paquetes como si todas estuvieran escaneando el objetivo.
* Nuestra IP real queda "mezclada" entre ellas.

Ejemplo con IPs aleatorias:

```bash
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

En el tráfico veremos varios paquetes SYN con **IPs falsas** más nuestra IP real.

📌 Importante:

* Los decoys **deberían estar vivos**; si no, se puede disparar protección tipo **SYN flood** o llamar la atención.
* Se puede usar también con IPs controladas (por ejemplo, otros VPS).
* Útil para confundir al administrador/IPS sobre quién está realmente escaneando.

---

## 🎭 Spoofing de IP de origen (-S) y selección de interfaz (-e)

Podemos probar si las reglas del firewall cambian al simular que venimos de otra IP.

Ejemplo:

### 1️⃣ Escaneo OS normal (puerto 445 filtrado)

```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O
```

Salida (resumen):

* `445/tcp filtered microsoft-ds`
* No se puede determinar bien el OS.

### 2️⃣ Escaneo OS con IP de origen falsa

```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

Aquí:

* `-S 10.129.2.200` → IP de origen spoofeada.
* `-e tun0` → interface por la que se envían los paquetes.

Resultado (resumen):

* `445/tcp open microsoft-ds`
* Ahora Nmap puede hacer mejores conjeturas sobre el sistema operativo.

👉 Conclusión: **el firewall aplica reglas distintas según la IP de origen**.

---

## 🌐 DNS Proxying y Source Port 53

Nmap realiza por defecto **reverse DNS lookups** para nombres de host.

* Esto suele hacerse por **UDP/53**.
* Históricamente, **TCP/53** se usaba para zone transfers o respuestas grandes (>512 bytes).
* Con IPv6 y DNSSEC, es más frecuente el uso de TCP/53.

### Uso de DNS interno

Podemos especificar servidores DNS propios:

```bash
--dns-server <ns1>,<ns2>
```

En una **DMZ**, los DNS internos suelen tener más confianza que los externos y pueden servirnos como canal hacia la red interna.

### 🔁 Usar el puerto 53 como source port (--source-port 53)

Muchos firewalls permiten el tráfico desde/hacia el **puerto 53** por ser tráfico DNS "legítimo".

Podemos aprovechar esto:

#### 🔹 SYN scan a un puerto filtrado

```bash
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace
```

Resultado:

* `50000/tcp filtered`

#### 🔹 Mismo scan, pero desde source port 53

```bash
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```

Resultado:

* `50000/tcp open ibm-db2`

👉 El firewall **confía más en el tráfico proveniente del puerto 53**, por lo que no lo filtra igual.

---

## 🧪 Confirmación con Netcat (ncat)

Una vez identificado que el puerto 53 como origen funciona, podemos probar una conexión manual:

```bash
ncat -nv --source-port 53 10.129.2.28 50000
```

Salida (ejemplo):

```text
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.2.28:50000.
220 ProFTPd
```

Esto confirma:

* El puerto **realmente está abierto**.
* El firewall/IPS estaba filtrando el escaneo tradicional, pero acepta tráfico desde `source-port 53`.

---

## 🔚 Resumen de Técnicas de Evasión vistas

1. **ACK scan (-sA)**

   * Determina si un puerto está **filtrado / no filtrado** por firewall.

2. **Decoys (-D)**

   * Mezclan la IP real entre IPs falsas para confundir al defensor.

3. **Spoofing de IP origen (-S) + interfaz (-e)**

   * Ver cómo cambian las reglas del firewall según la IP de origen.

4. **Uso del puerto 53 como source-port**

   * Aprovecha la confianza en el tráfico DNS.

5. **Detección de IDS/IPS** mediante comportamiento:

   * Escaneos agresivos + bloqueo de IP → presencia de IPS.

Todas estas técnicas deben usarse con cuidado, especialmente en entornos productivos, ya que pueden:

* Disparar alertas.
* Provocar bloqueos de IP.
* Ser consideradas comportamiento hostil fuera de un contexto de pentesting autorizado.

---

## 📚 Referencias

* Documentación oficial Nmap (Firewall/IDS Evasion): [https://nmap.org/book/man-bypass-firewalls-ids.html](https://nmap.org/book/man-bypass-firewalls-ids.html)

---


