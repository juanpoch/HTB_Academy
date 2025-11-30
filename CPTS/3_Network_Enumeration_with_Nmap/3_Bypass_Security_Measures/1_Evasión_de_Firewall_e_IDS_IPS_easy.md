# Laboratorio: Evasión de Firewall e IDS/IPS (Nivel Fácil)


---

## **Evasión de Firewall e IDS/IPS — Laboratorio**

Una empresa nos ha contratado para evaluar las defensas de seguridad de su infraestructura, incluyendo sus sistemas IDS e IPS.

El objetivo del cliente es **mejorar la seguridad de su red**, y por ello realizará ajustes en sus sistemas IDS/IPS después de cada prueba en la que logremos evadir sus controles o generar alertas.

Sin embargo, **no conocemos las reglas ni la lógica** detrás de las modificaciones que implementarán.

---

## 🎯 **Objetivo del laboratorio**

Nuestro objetivo es **obtener información específica sobre el sistema protegido**, enfrentándonos a diferentes escenarios donde las reglas del IDS/IPS irán cambiando.

Para ello:

* Solo contamos con **una máquina protegida** por IDS/IPS.
* Esa máquina es la única que podemos escanear y atacar.
* El comportamiento del IDS/IPS cambiará a medida que provoquemos alertas.

---

## 📊 **Página de estado del IDS/IPS**

Para aprender cómo se comporta un IDS/IPS ante distintos tipos de tráfico y para comprender cuándo estamos siendo detectados, disponemos de una página especial:

```
http://<target>/status.php
```

Esta página muestra:

* Número de **alertas** generadas por nuestras acciones.
* Indicadores sobre si estamos siendo detectados.

💡 **Dato importante:** Si acumulamos demasiadas alertas, **seremos bloqueados**.
Por eso debemos realizar nuestros escaneos y pruebas **de la forma más silenciosa posible**.

---

### Preguntas

#### Nuestro cliente desea saber si podemos identificar el sistema operativo que utiliza su máquina. Envíe el nombre del sistema operativo como respuesta.

`Pista`: Recuerda que no es necesario proporcionar una versión. Piensa en qué servicios pueden darte información sobre el sistema operativo. Tras entrevistar a los administradores, descubrimos que quieren evitar que los hosts vecinos con su máscara de subred /24 se comuniquen entre sí.



`IP`: `10.129.153.253 `

Realizamos un ping para ver si el host está activo:

```bash
nmap -sn -PE --disable-arp-ping -n --reason --packet-trace 10.129.153.253
```
<img width="1683" height="293" alt="image" src="https://github.com/user-attachments/assets/55629e12-a187-42ef-9c4b-c085373b739c" />

`Nota`: El TTL corresponde a Linux.


Hacemos un escaneo TCP SYN lo más silencioso posible:
```bash
nmap -sS --disable-arp-ping -Pn -n --packet-trace --reason --top-ports 10 10.129.153.253 --initial-rtt-timeout 3000ms
```
<img width="1279" height="771" alt="image" src="https://github.com/user-attachments/assets/5791bc9a-e453-42f6-b9dc-a63b4047113d" />

Puerto 22 y 80 abiertos.

Realizamos el mismo escaneo para esos 2 puertos, utilizando `--script banner` para realizar banner grabing:
```bash
nmap -sS --disable-arp-ping -Pn -n --packet-trace --reason -p22,80 10 10.129.153.253 --initial-rtt-timeout 3000ms --script banner
```
<img width="1331" height="805" alt="image" src="https://github.com/user-attachments/assets/ffeadd99-f6c9-46dd-804f-68cf85572da1" />
