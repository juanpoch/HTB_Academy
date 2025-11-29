# 🔍 Service Enumeration — Enumeración de Servicios

*Módulo: Network Enumeration with Nmap (HTB)*

La enumeración de servicios es una de las fases **más importantes del reconocimiento activo**. No basta con saber qué puertos están abiertos: necesitamos saber **qué servicios corren allí, qué versiones utilizan, y qué información exponen**.

Una correcta identificación de versiones nos permite:

* Buscar vulnerabilidades específicas.
* Analizar código fuente de esa versión.
* Ajustar exploits o payloads al sistema objetivo.

---

## 🧪 Service Version Detection (`-sV`)

Antes de ejecutar un escaneo completo de versiones, se recomienda hacer un **escaneo rápido** para tener un panorama general. Esto genera menos tráfico, disminuyendo la probabilidad de detección.

Luego, podemos correr:

```bash
sudo nmap 10.129.2.28 -p- -sV
```

Durante el escaneo, podés presionar **[Space Bar]** para ver el progreso:

```text
Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 3.64% done; ETC: 19:45
```

### Mostrar progreso automáticamente:

```bash
sudo nmap 10.129.2.28 -p- -sV --stats-every=5s
```
`Nota`: Podemos especificar minutos con `m`

### Aumentar el nivel de verbosidad

```bash
sudo nmap 10.129.2.28 -p- -sV -v
```

Esto hace que los puertos se muestren **a medida que son descubiertos**.

---

## 🏷️ Banner Grabbing y detección automática

Una vez finalizado el escaneo, Nmap muestra servicios y versiones:

```text
22/tcp open ssh   OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open http  Apache httpd 2.4.29 (Ubuntu)
995/tcp open ssl/pop3 Dovecot pop3d
```

Nmap obtiene esta información:

1. **Leyendo el banner del servicio.**
2. Si el banner no basta → usa un **sistema de firmas** (más lento).

Sin embargo, a veces Nmap **no muestra información importante** que sí está en los banners.

Ejemplo:

```text
220 inlane ESMTP Postfix (Ubuntu)
```

Aquí el servidor indica explícitamente que es **Ubuntu**, pero Nmap no lo mostró en la tabla final.

---

## 🧩 Viendo lo que Nmap *sí* recibió (pero no mostró)

Utilizamos un escaneo con trazado de paquetes (`--packet-trace`):

```bash
sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace
```

Salida relevante:

```text
READ SUCCESS ... 35 bytes: 220 inlane ESMTP Postfix (Ubuntu)
```

El banner revela **sistema operativo**, pero Nmap no lo imprime en la tabla final.

---

## 📡 Entendiendo los banners con nc + tcpdump

Podemos conectarnos manualmente al servicio SMTP para ver el banner nosotros mismos.

### 1. Capturamos tráfico con tcpdump

```bash
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
```

### 2. Nos conectamos al puerto 25

```bash
nc -nv 10.129.2.28 25
```

### Resultado:

```text
220 inlane ESMTP Postfix (Ubuntu)
```

### 3. Tráfico observado con tcpdump

```text
18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], seq 1798872233, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 331260178 ecr 0,sackOK,eol], length 0
18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], seq 1130574379, ack 1798872234, win 65160, options [mss 1460,sackOK,TS val 1800383922 ecr 331260178,nop,wscale 7], length 0
18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 1, win 2058, options [nop,nop,TS val 331260304 ecr 1800383922], length 0
18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.], seq 1:36, ack 1, win 510, options [nop,nop,TS val 1800383985 ecr 331260304], length 35: SMTP: 220 inlane ESMTP Postfix (Ubuntu)
18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 36, win 2058, options [nop,nop,TS val 331260368 ecr 1800383985], length 0
```
`Notar`:
```text
[PSH-ACK] SMTP: 220 inlane ESMTP Postfix (Ubuntu)
```

---

## 🧬 Análisis del tráfico TCP

El flujo del protocolo TCP en este ejemplo es:

1. **SYN** → Cliente inicia conexión.
2. **SYN-ACK** → Servidor acepta conexión.
3. **ACK** → Cliente confirma la conexión.

> Esto completa el **three-way handshake**.

4. **PSH-ACK** → El servidor envía el banner SMTP.
5. **ACK** → Cliente confirma recepción.

El flag **PSH (Push)** indica que el servidor envía datos inmediatamente (el banner). El flag **ACK** confirma la recepción.

Esto muestra que **Nmap sí recibe esta información**, pero su parser a veces **omite detalles del banner**.

Por eso, un pentester experto siempre complementa la enumeración automática con:

* `nc` para conexiones manuales
* `telnet` o `openssl s_client` para servicios cifrados
* inspección directa con `tcpdump` o `Wireshark`

---

## 📌 Opciones utilizadas en los ejemplos

| Opción               | Descripción                                    |
| -------------------- | ---------------------------------------------- |
| `-p-`                | Escanea todos los puertos (1–65535).           |
| `-sV`                | Detección de servicios y versiones.            |
| `-v`                 | Aumenta la verbosidad.                         |
| `--stats-every=5s`   | Muestra progreso cada 5 segundos.              |
| `-Pn`                | Sin ping ICMP.                                 |
| `-n`                 | Sin DNS.                                       |
| `--disable-arp-ping` | Evita ping ARP.                                |
| `--packet-trace`     | Muestra todos los paquetes enviados/recibidos. |

---


---

### Preguntas

#### Enumere todos los puertos y sus servicios. Uno de los servicios contiene la bandera que debe enviar como respuesta.

Hacemos nuestro escaneo TCP SYN:
<img width="1071" height="500" alt="image" src="https://github.com/user-attachments/assets/c8ee2f65-b00f-450c-856d-991584482f36" />

Luego hacemos un escaneo de versiones a los puertos encontrados abiertos:
<img width="1322" height="684" alt="image" src="https://github.com/user-attachments/assets/f9004334-65a1-46db-ab99-55878b337727" />



Inspeccionamos la salida mientras escaneamos y encontramos la flag correspondiente al puerto 31337
<img width="1771" height="738" alt="image" src="https://github.com/user-attachments/assets/79599168-3ae4-4838-b624-49ef0b0e6dda" />

`Nota`: Fijarse que en la salida común no aparece el banner obtenido:
<img width="1823" height="520" alt="image" src="https://github.com/user-attachments/assets/619fe535-a7a5-4656-9a88-da697e4a0b72" />

----

Alternativa 2:

Probar con tcpdump y nc:

<img width="1064" height="97" alt="image" src="https://github.com/user-attachments/assets/1b9a5d8e-a93e-40eb-9671-f3473e9a250c" />


`Nota`: Cuando hacemos `host A and B` significa `Capturar tráfico cuyo origen o destino incluya a A y también a B en la misma sesión`.

Hacemos banner grabbing:
<img width="618" height="119" alt="image" src="https://github.com/user-attachments/assets/6c3e8791-1d32-4965-82ea-af44bd059c1b" />

