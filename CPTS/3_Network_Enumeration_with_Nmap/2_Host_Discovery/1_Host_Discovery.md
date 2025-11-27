# 🌐 Host Discovery con Nmap

*Módulo: Network Enumeration with Nmap (HTB)*

La fase de **Host Discovery** es esencial cuando realizamos un pentest interno, ya que nos permite identificar qué sistemas están activos dentro de una red antes de proceder con enumeraciones más profundas.

---

## 📌 ¿Qué es Host Discovery?

Cuando ingresamos a una red corporativa, lo primero es determinar **qué hosts están encendidos** y disponibles para escanear. Nmap ofrece múltiples formas de detectar si un host está vivo, siendo las más comunes:

* **ICMP Echo Requests (ping)**
* **ARP Requests** (en redes locales)

Cada método puede verse afectado por firewalls o políticas de red, por lo que es importante conocer varias técnicas.

---

## 📌 Recomendación Profesional

Siempre debemos **guardar todos los escaneos**. Esto permite:

* Comparar resultados.
* Documentar hallazgos.
* Identificar inconsistencias entre herramientas.
* Asegurar trazabilidad en informes.

Nmap permite almacenar resultados en múltiples formatos con `-oA`.

---

# 🧪 Escaneo de un Rango de Red

```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

### ✔️ Opciones utilizadas

| Opción          | Descripción                                                |
| --------------- | ---------------------------------------------------------- |
| `10.129.2.0/24` | Rango de red objetivo                                      |
| `-sn`           | Desactiva el port scanning (solo host discovery)           |
| `-oA tnet`      | Guarda resultados en todos los formatos con prefijo "tnet" |

### 📝 Nota

Este método funciona **solo si el firewall permite ICMP o ARP**. Si no, los hosts aparecerán como inactivos, aunque estén encendidos.

---

# 📄 Escaneo a partir de una Lista de IPs

Es común que en un pentest se nos entregue un archivo con hosts específicos.

Ejemplo de lista:

```
cat hosts.lst
10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```

Escaneo:

```
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

### ✔️ Opciones utilizadas

| Opción          | Descripción                |
| --------------- | -------------------------- |
| `-sn`           | Solo host discovery        |
| `-oA tnet`      | Guarda los resultados      |
| `-iL hosts.lst` | Lee las IPs desde la lista |

🔎 Resultado del módulo: solo **3 de 7 hosts** respondieron. Esto puede significar:

* Los demás hosts **no responden ICMP** (firewall), o
* Verdaderamente están apagados.

---

# 🔢 Escaneo de Múltiples IPs

## ✔️ IPs individuales

```
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20
```

## ✔️ Rango en un octeto

```
sudo nmap -sn -oA tnet 10.129.2.18-20
```

Ambas formas producen el mismo resultado cuando las IPs están consecutivas.

---

# 🎯 Escaneo de un Único Host

Antes de enumerar puertos, primero debemos saber si el host está vivo:

```
sudo nmap 10.129.2.18 -sn -oA host
```

Salida relevante:

```
Host is up (0.087s latency).
MAC Address: DE:AD:00:00:BE:EF
```

### ✔️ Opciones utilizadas

| Opción        | Descripción         |
| ------------- | ------------------- |
| `10.129.2.18` | Host objetivo       |
| `-sn`         | Solo host discovery |
| `-oA host`    | Guarda resultados   |

### 🧠 Detalle importante

Cuando usamos `-sn`, Nmap **envía primero ARP requests**, no ICMP.
Si la red es local, ARP es el método más confiable.

---

# 🔍 Forzar el uso de ICMP Echo Requests (-PE)

```
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace
```

Salida relevante:

```
SENT ARP who-has ...
RCVD ARP reply ...
```

Esto confirma que **Nmap usa ARP antes que ICMP**, a menos que lo forcemos a deshabilitar ARP.

---

# 🧪 Ver por qué Nmap considera que un host está "alive" (--reason)

```
sudo nmap 10.129.2.18 -sn -oA host -PE --reason
```

Salida:

```
Host is up, received arp-response
```

Esto nos indica **el motivo exacto** por el que Nmap marca el host como activo.

---

# 🚫 Desactivar ARP para usar solo ICMP (--disable-arp-ping)

Para investigar ICMP a fondo:

```
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```

Salida relevante:

```
SENT ICMP Echo request
RCVD ICMP Echo reply
```

Esto demuestra que:

* ARP es el método preferido en redes locales.
* ICMP solo se usa si ARP está deshabilitado.

---

## 📌 Nota Final

Los detalles importan. Observar diferencias entre ARP, ICMP y las respuestas de los hosts permite:

* Identificar sistemas vivos.
* Inferir configuraciones de red.
* Deducir firewalls y filtrado.

Más estrategias:
🔗 [https://nmap.org/book/host-discovery-strategies.html](https://nmap.org/book/host-discovery-strategies.html)


---

### Preguntas

Con base en el último resultado, determine a qué sistema operativo pertenece. Envíe el nombre del sistema operativo como resultado.

El TTL = 128 es un indicador clásico de que el host está corriendo Windows.

| TTL recibido | Sistema operativo típico |
| ------------ | ------------------------ |
| **64**       | Linux / Unix / macOS     |
| **128**      | **Windows**              |
| **255**      | Cisco / Equipos de red   |
