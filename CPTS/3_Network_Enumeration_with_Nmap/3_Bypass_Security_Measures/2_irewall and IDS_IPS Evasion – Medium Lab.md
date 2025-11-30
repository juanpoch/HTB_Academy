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

Realizamos un ping para ver si el host está activo:

```bash
nmap -sn -PE --disable-arp-ping -n --reason --packet-trace 10.129.2.48
```
<img width="1360" height="302" alt="image" src="https://github.com/user-attachments/assets/c5cbe903-26ca-45c6-aa0f-61329cf618c3" />
