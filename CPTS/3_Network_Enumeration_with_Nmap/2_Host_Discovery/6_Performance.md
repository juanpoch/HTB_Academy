# Nmap — Performance

Este documento resume y explica en detalle la sección **Performance** del módulo *Network Enumeration with Nmap* de Hack The Box. Está escrito en español y en formato Markdown para ser almacenado en GitHub.

---

# 🏎️ Optimización del Rendimiento en Nmap

Cuando escaneamos redes grandes o trabajamos con poco ancho de banda, optimizar el rendimiento de Nmap es esencial. Nmap permite controlar múltiples aspectos del escaneo para acelerar su ejecución, pero **toda optimización tiene un costo**: acelerar demasiado puede hacer que Nmap pierda hosts o puertos abiertos.

A continuación analizamos:

* Timeouts (RTT)
* Retries
* Rate de paquetes
* Timing templates (-T0 a -T5)

---

# ⏱️ 1. Timeouts (RTT)

El RTT (*Round-Trip-Time*) mide cuánto tarda un paquete en ir y volver. Nmap ajusta automáticamente sus valores, pero podemos configurarlos manualmente:

* **--initial-rtt-timeout <valor>** — tiempo inicial para esperar respuesta.
* **--max-rtt-timeout <valor>** — tiempo máximo permitido antes de descartar respuesta.

### 📌 Comparación

#### 🔹 Scan por defecto

```
sudo nmap 10.129.2.0/24 -F
```

**Resultado:** 39.44 segundos

#### 🔹 Scan optimizado (RTT reducido)

```
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

**Resultado:** 12.29 segundos

📉 Pero detectó **menos hosts (8 vs 10)**.

👉 Conclusión: *Reducir demasiado los timeouts hace que Nmap ignore hosts lentos.*

---

# 🔁 2. Max Retries

Nmap reenvía paquetes hasta **10 veces por defecto** si no recibe respuesta.

Podemos acelerar el escaneo usando:

```
--max-retries 0
```

Esto indica: *"Si no responde el primer intento, NO reintentes"*.

### 📌 Comparación

#### 🔹 Scan por defecto

```
sudo nmap 10.129.2.0/24 -F | grep "/tcp" | wc -l
```

**Resultado:** 23 puertos abiertos

#### 🔹 Scan con retries reducidos

```
sudo nmap 10.129.2.0/24 -F --max-retries 0 | grep "/tcp" | wc -l
```

**Resultado:** 21 puertos abiertos

👉 Conclusión: *Más rápido, pero puede omitir puertos.*

---

# 📡 3. Modificar el Rate de paquetes (--min-rate)

Podemos definir cuántos paquetes mínimos por segundo debe enviar Nmap.

Ejemplo:

```
--min-rate 300
```

Esto fuerza a Nmap a enviar **300 paquetes por segundo o más**.

### 📌 Comparación

#### 🔹 Scan por defecto

```
sudo nmap 10.129.2.0/24 -F -oN tnet.default
```

**Duración:** 29.83 s — **23 puertos detectados**

#### 🔹 Scan optimizado

```
sudo nmap 10.129.2.0/24 -F --min-rate 300 -oN tnet.minrate300
```

**Duración:** 8.67 s — **23 puertos detectados**

👉 Excelente mejora sin pérdida de calidad.

---

# ⏳ 4. Timing Templates (-T0 a -T5)

Nmap incluye plantillas de tiempo predefinidas que ajustan automáticamente muchos parámetros:

| Valor | Nombre     | Descripción                   |
| ----- | ---------- | ----------------------------- |
| -T0   | paranoid   | Lento, muy sigiloso           |
| -T1   | sneaky     | Muy lento, sigiloso           |
| -T2   | polite     | Limita carga en la red        |
| -T3   | normal     | *Default*                     |
| -T4   | aggressive | Muy rápido, menos sigiloso    |
| -T5   | insane     | Máxima velocidad, riesgo alto |

Los valores mayores producen más velocidad, pero también:

* más probabilidad de *false negatives* (puertos perdidos)
* más probabilidad de levantar alarmas en IDS/IPS

### 📌 Comparación

#### 🔹 Default (T3)

```
sudo nmap 10.129.2.0/24 -F -oN tnet.default
```

**Duración:** 32.44 s — 23 puertos

#### 🔹 Insane (T5)

```
sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
```

**Duración:** 18.07 s — 23 puertos

👉 Acelera bastante, pero puede activar firewalls.

---

# 📘 Conclusiones

* Optimizar Nmap **siempre implica compromisos**.
* Escaneos rápidos pueden **perder información**.
* En entornos controlados (white‑box), usar `--min-rate` y plantillas altas puede ser ideal.
* En pentesting real (black‑box), usar `-T2` o `-T3` para evitar detección.

---

# 📚 Recursos

* Documentación oficial: [https://nmap.org/book/man-performance.html](https://nmap.org/book/man-performance.html)
* Timing templates detallados: [https://nmap.org/book/performance-timing-templates.html](https://nmap.org/book/performance-timing-templates.html)

---
