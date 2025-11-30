# 🛡️ Firewall and IDS/IPS Evasion – Medium Lab

## 🧪 Escenario del Laboratorio

Tras completar la primera prueba y entregar nuestro reporte, los administradores de la empresa ajustaron y reforzaron las configuraciones del **firewall** y del **IDS/IPS**. Durante la reunión previa al segundo test, escuchamos que:

* No estaban conformes con las configuraciones anteriores.
* Consideran que la red puede filtrarse de manera más estricta.
* Han aplicado nuevas reglas de seguridad.

Como resultado, esta nueva ronda de pruebas será más difícil y requerirá técnicas adicionales para evitar alertas.

---

> **Para resolver este ejercicio debemos usar el protocolo UDP desde la VPN.**



---

### Preguntas

#### Tras transferir las configuraciones al sistema, nuestro cliente desea saber si es posible conocer la versión del servidor DNS de nuestro objetivo. Envíe la versión del servidor DNS del objetivo como respuesta.

`Pista`: Durante la reunión, los administradores hablaron sobre el host que probamos como un servidor de acceso público que no se mencionó antes.

`IP`: `10.129.2.48`

- Realizamos un ping para ver si el host está activo:

```bash
nmap -sn -PE --disable-arp-ping -n --reason --packet-trace 10.129.2.48
```
<img width="1360" height="302" alt="image" src="https://github.com/user-attachments/assets/c5cbe903-26ca-45c6-aa0f-61329cf618c3" />


- Hacemos un escaneo TCP SYN lo más silencioso posible:

```bash
nmap -sS --disable-arp-ping -Pn -n --packet-trace --reason --top-ports 10 10.129.2.48 --initial-rtt-timeout 3000ms
```

<img width="707" height="282" alt="image" src="https://github.com/user-attachments/assets/1736eb7f-a0d0-4625-ae75-7ba372c010ba" />

Puertos abiertos: 21, 22, 80, 110, 139

Si hacemos el mísmo escaneo para el puerto 53 nos dá cerrado:
<img width="1452" height="407" alt="image" src="https://github.com/user-attachments/assets/b311ccd0-e812-436b-a103-f6870583d08f" />


Hacemos un escaneo UDP al puerto 53:

```bash
nmap -sU -p 53 --script dns-version -T2 --max-retries 1 10.129.2.48
```
<img width="920" height="256" alt="image" src="https://github.com/user-attachments/assets/907104cd-e5ca-4858-817b-a75adc49ddc1" />


Como el puerto está abierto, lo enumeramos con el script `dns-nsid.nse` enumera versiones dns:
```bash
nmap -sU -p 53 --script dns-nsid -T2 --max-retries 1 10.129.2.48
```

<img width="1153" height="321" alt="image" src="https://github.com/user-attachments/assets/e91974c4-fb8d-4602-9c0e-33ac574b5c16" />

- `bind.version`: HTB{GoTtgUnyze9Psw4vGjcuMpHRp}

