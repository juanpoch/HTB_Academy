# Métodos de Autenticación en Redes Wi-Fi

## Introducción

En las redes Wi-Fi existen dos métodos principales de autenticación: **Autenticación de Sistema Abierto (Open System Authentication)** y **Autenticación con Clave Compartida (Shared Key Authentication)**. Aunque hoy en día existen protocolos más avanzados como WPA3 y métodos empresariales con 802.1X, estos dos representan las bases históricas de cómo los clientes y puntos de acceso se identifican mutuamente.

---

## Autenticación de Sistema Abierto (Open System Authentication)

Este método permite que cualquier dispositivo se conecte a la red sin necesidad de proporcionar una contraseña. Su flujo de conexión es simple:

1. El cliente envía una **solicitud de autenticación** al punto de acceso (AP).
2. El AP responde con una **respuesta de autenticación** (generalmente aceptada).
3. El cliente envía una **solicitud de asociación**.
4. El AP responde con una **respuesta de asociación**.

> ⚠️ No se verifica ninguna clave o credencial. Este método es común en redes públicas y abiertas.

### Ventajas

* Fácil acceso para usuarios.
* Ideal para redes de invitados o cafés.

### Desventajas

* **No hay cifrado por defecto.**
* Vulnerable a ataques de sniffing y rogue APs.

---

## Autenticación con Clave Compartida (Shared Key Authentication)

Este método utiliza una clave precompartida (PSK) conocida por el cliente y el AP. Se emplea un **desafío (challenge)** para verificar que ambas partes conocen la clave:

### Proceso con WEP

1. El cliente envía una **solicitud de autenticación**.
2. El AP responde con un **texto de desafío**.
3. El cliente **cifra el desafío con la clave WEP** y lo devuelve.
4. El AP lo **descifra y verifica** si coincide.

> 🔒 Utiliza el algoritmo RC4 y CRC-32 (message integrity), hoy considerados inseguros.

### Proceso con WPA/WPA2

WPA reemplazó WEP y mejoró considerablemente la seguridad usando TKIP, y luego AES con WPA2.

1. El cliente inicia una **solicitud de autenticación**.
2. El AP responde con una **respuesta positiva**.
3. Ambas partes derivan una **clave PMK (Pairwise Master Key)** desde la PSK (contraseña).
4. Se ejecuta el **4-Way Handshake** para verificar mutua posesión de la PSK.

### WPA3 y SAE

WPA3 introduce SAE (Simultaneous Authentication of Equals), reemplazando la PSK con un protocolo más seguro ante ataques de diccionario.

* Cada sesión usa un secreto distinto (Forward Secrecy).
* Brinda mayor protección contra ataques offline.
* **No se transmite directamente la contraseña.**

---

## Comparativa de Métodos

| Método      | Cifrado      | Autenticación    | Seguridad | Uso Actual          |
| ----------- | ------------ | ---------------- | --------- | ------------------- |
| Open System | Ninguno      | Ninguna          | Muy baja  | Público / Invitados |
| WEP         | RC4 + CRC-32 | Clave compartida | Baja      | Obsoleto            |
| WPA         | TKIP + MIC   | PSK / 802.1X     | Media     | Heredado            |
| WPA2        | AES + CCMP   | PSK / 802.1X     | Alta      | Estándar            |
| WPA3        | AES + GCMP   | SAE / 802.1X     | Muy alta  | Moderno             |

---

## Conclusión

Entender estos mecanismos es clave para analizar capturas de tráfico, simular ataques y entender los fundamentos del ciclo de autenticación Wi-Fi. Mientras que los métodos abiertos ofrecen facilidad, los métodos con clave compartida como WPA2 o WPA3 brindan la protección necesaria frente a ataques pasivos y activos.
