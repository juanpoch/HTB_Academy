# Interfaces Wi-Fi para Pentesting

## Introducción

Las interfaces inalámbricas (Wi-Fi) son un componente fundamental para cualquier proceso de pentesting Wi-Fi. A través de estas interfaces, nuestras máquinas transmiten y reciben datos. Sin una interfaz adecuada, no podríamos interactuar con las redes inalámbricas ni capturar paquetes de forma efectiva.

En esta sección se detallan los aspectos clave a tener en cuenta al elegir y configurar una interfaz Wi-Fi para pruebas de penetración.

---

## Cómo Elegir la Interfaz Correcta

### Características esenciales:

* Soporte para **modo monitor**.
* Capacidad de **inyección de paquetes**.
* Compatibilidad con **IEEE 802.11ac** o superior.
* Soporte para bandas de **2.4 GHz y 5 GHz**.

> ⚠️ Algunas tarjetas de 2.4 GHz pueden ser más efectivas que tarjetas dual-band, dependiendo del soporte de drivers y chipsets.

### Chipset y Controladores

El **chipset** y su **driver** son factores decisivos. Algunas opciones comunes y bien soportadas por herramientas como `aircrack-ng`, `hcxdumptool`, y `airgeddon` incluyen:

* Atheros AR9271
* Ralink RT3070
* MediaTek MT7612U

> Las tarjetas USB externas generalmente requieren instalación manual de drivers. Las tarjetas internas pueden tener soporte limitado para modo monitor o inyección.

---

## Verificando la Potencia y Región de Transmisión

Con `iwconfig` puedes verificar la potencia de transmisión (TX power):

```bash
$ iwconfig
```

Con `iw reg get`, puedes consultar la configuración regional:

```bash
$ iw reg get
```

Para cambiarla (por ejemplo, a EE.UU.):

```bash
$ sudo iw reg set US
```

> 🔺 Cambiar la región puede desbloquear canales y aumentar el límite de TX power, pero puede ser ilegal en algunos países.

Para aumentar la potencia:

```bash
$ sudo ifconfig wlan0 down
$ sudo iwconfig wlan0 txpower 30
$ sudo ifconfig wlan0 up
```

Verifica el resultado nuevamente con `iwconfig`.

---

## Comprobando Capacidades de la Interfaz

Usa `iw list` para conocer las capacidades técnicas de la interfaz:

```bash
$ iw list
```

Busca información como:

* Soporte de modos: monitor, AP, P2P, mesh...
* Cifrados compatibles: WEP, TKIP, CCMP, GCMP...
* Frecuencias habilitadas (2.4/5 GHz)
* Soporte para WPA3 (SAE)

> 📌 Esto es crucial para confirmar si tu adaptador soporta ciertas pruebas (por ejemplo, autenticación WPA3).

---

## Escaneando Redes Disponibles

Puedes usar `iwlist` para escanear redes:

```bash
$ iwlist wlan0 scan | grep 'Cell\|Quality\|ESSID\|IEEE'
```

Este comando muestra:

* Dirección MAC del AP
* Calidad de señal
* SSID
* Tipo de cifrado

---

## Cambio de Canal y Frecuencia

### Ver canales disponibles:

```bash
$ iwlist wlan0 channel
```

### Cambiar canal:

```bash
$ sudo ifconfig wlan0 down
$ sudo iwconfig wlan0 channel 6
$ sudo ifconfig wlan0 up
```

### Cambiar frecuencia directamente:

```bash
$ sudo ifconfig wlan0 down
$ sudo iwconfig wlan0 freq 5.52G
$ sudo ifconfig wlan0 up
```

Verificar frecuencia actual:

```bash
$ iwlist wlan0 frequency | grep Current
```

> ✅ Cambiar canal/frecuencia puede ayudar a reducir interferencias o apuntar a redes específicas.

---

## Conclusión

Elegir y configurar correctamente tu interfaz Wi-Fi es clave para realizar pruebas efectivas. Factores como el soporte de modo monitor, la potencia, los controladores y el tipo de chipset influyen directamente en la calidad de tus capturas y la capacidad de realizar ataques. Asegurarse de que la tarjeta soporte los protocolos y frecuencias objetivo es el primer paso antes de lanzar cualquier ataque o recolección de handshakes.

En la siguiente sección exploraremos los **modos de operación de una interfaz Wi-Fi**, como modo monitor, managed, master y otros, fundamentales para el pentesting inalámbrico.

---

**Autor del writeup:** \[Tu Nombre / Alias]
**Repositorio GitHub:** \[enlace-al-repo]
