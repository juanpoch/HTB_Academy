# Wi-Fi Penetration Testing Basics

## Introducción

En el mundo interconectado de hoy, las redes Wi-Fi se han vuelto omnipresentes, funcionando como columna vertebral de nuestra conectividad digital. Sin embargo, esta conveniencia también trae consigo riesgos de seguridad que pueden ser explotados por actores maliciosos.

El pentesting Wi-Fi,  es un proceso crucial utilizado por profesionales de la ciberseguridad para evaluar el estado de seguridad de las redes Wi-Fi. Al analizar sistemáticamente frases de acceso, configuraciones, infraestructura y dispositivos cliente, los pentesters pueden descubrir vulnerabilidades que podrían comprometer la seguridad de la red.

Este módulo explora los principios fundamentales del pentesting Wi-Fi, cubriendo aspectos clave y técnicas esenciales utilizadas para evaluar y reforzar la seguridad de las redes inalámbricas.

---

## Tipos de Autenticación Wi-Fi

Los tipos de autenticación Wi-Fi son fundamentales para proteger las redes inalámbricas y evitar accesos no autorizados. A continuación, se describen los principales protocolos de seguridad:

### 1. **WEP (Wired Equivalent Privacy)**

* Primer protocolo de seguridad Wi-Fi.
* Utiliza cifrado RC4.
* Actualmente es considerado obsoleto e inseguro debido a vulnerabilidades conocidas.

### 2. **WPA (Wi-Fi Protected Access)**

* Mejora temporal sobre WEP.
* Introduce un cifrado TKIP (Temporal Key Integrity Protocol).
* Ofrece mayor seguridad, pero sigue siendo vulnerable ante ciertos ataques.

### 3. **WPA2 (Wi-Fi Protected Access II)**

* Estándar dominante por muchos años.
* Usa AES (Advanced Encryption Standard) para cifrado fuerte.
* Tiene dos variantes:

  * **WPA2-PSK (Personal)**: Autenticación basada en contraseña compartida.
  * **WPA2-Enterprise**: Usa 802.1X y servidores RADIUS para autenticación de usuarios individuales.

    * Métodos comunes:

      * EAP-TTLS/PAP
      * PEAP-MSCHAPv2

### 4. **WPA3 (Wi-Fi Protected Access III)**

* Estándar más reciente.
* Incluye mejoras como:

  * Cifrado individualizado.
  * Autenticación más robusta con SAE (Simultaneous Authentication of Equals).
* Variantes:

  * **WPA3-SAE (Personal)**
  * **WPA3-Enterprise**: Uso de EAP-TLS (basado en certificados).

### 5. **Autenticación basada en certificados (CBA)**

* Utilizada principalmente en entornos empresariales.
* Requiere infraestructura de PKI (Public Key Infrastructure).
* Ofrece autenticación fuerte mediante certificados digitales.

---

## Componentes Clave de un Pentest Wi-Fi

Un test de penetración Wi-Fi eficaz incluye los siguientes cuatro componentes esenciales:

### 1. **Evaluación de Frases de Acceso (Passphrases)**

* Se analiza la fortaleza de las contraseñas utilizadas en la red.
* Técnicas comunes:

  * Ataques por diccionario
  * Fuerza bruta
  * Cracking offline de handshakes
* Herramientas populares:

  * Aircrack-ng
  * Hashcat

### 2. **Evaluación de Configuración**

* Se revisan los ajustes del router o punto de acceso.
* Se busca:

  * Uso de protocolos obsoletos (WEP, WPA)
  * Canales abiertos innecesarios
  * Acceso remoto habilitado sin seguridad
  * Falta de segmentación de red (p. ej., sin red de invitados)

### 3. **Prueba de la Infraestructura**

* Análisis de la arquitectura de la red y dispositivos.
* Se exploran:

  * Firmware desactualizado
  * Fallos en configuraciones de APs
  * Debilidades en la implementación del protocolo 802.11

### 4. **Prueba de Clientes**

* Evaluación de los dispositivos conectados (laptops, smartphones, IoT).
* Análisis de:

  * Vulnerabilidades en drivers de red y sistemas operativos.
  * Fallos en software de conexión.
  * Comportamiento inseguro ante redes falsas (rogue APs).

---

##
