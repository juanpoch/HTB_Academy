# Firewall and IDS/IPS Evasion - Hard Lab



---

# 🛡️ Firewall e IDS/IPS Evasion – Hard Lab

Tras nuestra segunda ronda de pruebas, el cliente obtuvo nueva información valiosa. Luego de la reunión, decidieron enviar a uno de sus administradores a un curso de capacitación específico sobre sistemas IDS/IPS. Según nos informaron, la formación duró una semana.

Después de completar la capacitación, el administrador aplicó todas las medidas necesarias y realizó una reconfiguración completa del sistema de detección y prevención. Debido a estos cambios, el cliente quiere que ejecutemos **una nueva fase de pruebas**, ya que ciertos servicios han sido modificados y la comunicación requerida por el software interno también ha cambiado.

Nuestro objetivo en este laboratorio será determinar si todavía es posible obtener información sensible incluso con un IDS/IPS más estricto y reglas de firewall mejoradas.

---

## 🎯 Objetivo del laboratorio

El cliente quiere saber si aún es posible **identificar la versión del servicio** que mencionaron durante la reunión. Deberemos realizar un escaneo lo suficientemente silencioso y preciso para lograr descubrir dicha versión **sin activar las alertas del IDS**.

Una vez identificada la versión del servicio en cuestión, debemos **enviar la flag como respuesta final del ejercicio**.

---




### Preguntas

#### Ahora nuestro cliente quiere saber si es posible averiguar la versión de los servicios en ejecución. Identifique la versión del servicio al que se refería y envíe la marca como respuesta.

`Pista`: Nuestro cliente también mencionó que se vieron obligados a agregar un servicio que juega un papel vital para sus clientes porque requieren grandes cantidades de datos.

`IP`: `10.129.97.161`

- Realizamos un ping para ver si el host está activo:
```bash
nmap -sn -PE --disable-arp-ping -n --reason --packet-trace 10.129.97.161
```

<img width="1536" height="224" alt="image" src="https://github.com/user-attachments/assets/e64b9426-6c0c-4f4d-b6bc-2deb28a47432" />

El host está activo.
