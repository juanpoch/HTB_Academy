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


- Hacemos un escaneo TCP SYN lo más silencioso posible:
```bash
nmap -sS --disable-arp-ping -Pn -n --packet-trace --reason --top-ports 200 10.129.97.161 --initial-rtt-timeout 3000ms -T2
```

<img width="980" height="83" alt="image" src="https://github.com/user-attachments/assets/5a112e75-9d20-429f-80f9-4058ae242654" />

Puerto 80 abierto.

Volvemos a realizar un escaneo pero esta vez escaneamos los top 1000 puertos, utilizaremos decoy y DNS source port y disminuimos el `max-retires`:

```bash
nmap -sS --disable-arp-ping -Pn -n --packet-trace --reason --top-ports 1000 10.129.97.161 --initial-rtt-timeout 3000ms -T2 -D RND:20 --source-port 53 --max-retries 2
```

<img width="910" height="101" alt="image" src="https://github.com/user-attachments/assets/9193a2ee-a042-4ec1-b2e8-ecd906eddd69" />

Encontramos el puerto 50000 open.


Procedemos a realizar un escaneo de versiones con los mismos parámetros seteados para el escaneo anterior:

```bash
nmap -sV --disable-arp-ping -Pn -n --packet-trace --reason -p50000 10.129.97.161 --initial-rtt-timeout 3000ms -T2 -D RND:20 --source-port 53 --max-retries 2
```

<img width="646" height="88" alt="image" src="https://github.com/user-attachments/assets/09de6c8f-5cb0-4115-a0f7-ff38de5ebcd7" />

No encontramos la flag, procedemos a realizar un escaneo UDP:
```bash
nmap -sU --disable-arp-ping -Pn -n --packet-trace --reason --top-ports 1000 10.129.97.161 --initial-rtt-timeout 3000ms -T2 -D RND:20 --source-port 53 --max-retries 2 
```

<img width="858" height="105" alt="image" src="https://github.com/user-attachments/assets/b6fe1a56-40e4-4433-ae9f-a682eeb4418c" />
