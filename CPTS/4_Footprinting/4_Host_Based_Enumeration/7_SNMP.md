# 📡 SNMP 

---

# 1️⃣ ¿Qué es SNMP y para qué sirve?

**SNMP (Simple Network Management Protocol)** es un protocolo diseñado para **monitorizar y administrar dispositivos de red**.

En palabras simples:

👉 Permite preguntarle cosas a un dispositivo.
👉 Permite cambiar configuraciones remotamente.

Imaginá que tenés un router en una empresa. Con SNMP podrías:

* Ver cuánta CPU está usando.
* Ver el tráfico de red.
* Saber si una interfaz está caída.
* Cambiar ciertos parámetros de configuración.

Por eso no es solo un protocolo de "consulta" — también puede **modificar valores**.

---

# 2️⃣ ¿Qué dispositivos suelen tener SNMP?

Muchísimos dispositivos de infraestructura lo usan:

* Routers
* Switches
* Firewalls
* Servidores
* Impresoras
* Dispositivos IoT
* Equipamiento industrial

En entornos corporativos es extremadamente común.

---

# 3️⃣ Cómo funciona SNMP (modelo simple)

SNMP funciona con un modelo:

## 🖥 Agente ↔ Cliente

### 🔹 Agente SNMP

Es el servicio que corre dentro del dispositivo (router, switch, etc).

Es quien "tiene la información".

### 🔹 Cliente SNMP

Es el sistema que consulta o modifica esa información.

Es quien hace las preguntas.

---

# 4️⃣ Puertos que usa SNMP

SNMP usa UDP.

* **UDP 161 → Consultas normales (GET, SET, WALK)**
* **UDP 162 → Traps (alertas automáticas)**

---

# 5️⃣ ¿Qué significa que SNMP puede modificar cosas?

No solo se limita a enviar información.

También puede enviar **comandos de control**.

Ejemplo:

* El cliente puede cambiar el nombre del dispositivo.
* Puede modificar ciertos parámetros.
* Puede activar o desactivar funciones.

Esto ocurre mediante comandos enviados al **puerto UDP 161**.

Desde el punto de vista de seguridad:

⚠ Si está mal configurado, puede permitir cambios no autorizados.

---

# 6️⃣ ¿Qué son los SNMP Traps? (UDP 162)

En la comunicación clásica:

Cliente → Pregunta
Servidor → Responde

Pero SNMP agrega algo más:

## 🔔 Traps

Un **trap** es un mensaje que el dispositivo envía automáticamente cuando ocurre un evento.

Ejemplos:

* Se cae una interfaz de red
* Se reinicia el dispositivo
* Se supera un umbral de CPU

El dispositivo envía esa alerta sin que nadie la haya pedido.

Esto viaja por **UDP 162**.

---

# 7️⃣ ¿Cómo sabe SNMP qué información pedir?

Acá aparece algo clave:

## 📌 OID (Object Identifier)

Cada dato que puede consultarse en un dispositivo tiene un identificador único llamado **OID**.

Un OID es como una dirección.

Ejemplo conceptual:

* Un OID para la CPU
* Un OID para el uptime
* Un OID para el nombre del sistema

Si el cliente quiere saber el uptime, debe pedir el OID correspondiente.

Sin OIDs, SNMP no puede funcionar.

---

# 8️⃣ ¿Por qué es importante en pentesting?

Porque muchas veces:

* Está habilitado innecesariamente
* Usa versiones antiguas (v1 o v2c)
* Usa comunidades por defecto como "public"

Si se puede consultar libremente, puede revelar:

* Información del sistema operativo
* Interfaces de red
* Usuarios
* Información interna de la infraestructura

Por eso es una fase clave en enumeración.

---

# 9️⃣ Versiones de SNMP

* **SNMPv1** → Antigua, sin seguridad real
* **SNMPv2c** → Similar a v1, usa comunidades
* **SNMPv3** → Introduce autenticación y cifrado

En la práctica, muchas redes todavía usan v1 o v2c.

---


---

# 🌳 SNMP – MIB y OID

---

# 1️⃣ El Problema que Resuelve la MIB

Imaginemos esta situación:

Tenés:

* Un router Cisco
* Un switch HP
* Un firewall Fortinet

Todos usan SNMP.

Pero… ¿cómo hace un cliente SNMP para entenderse con todos si cada fabricante diseña sus dispositivos de forma diferente?

👉 Para resolver ese problema se creó la **MIB (Management Information Base)**.

La MIB es el "diccionario universal" que permite que SNMP funcione de manera estándar entre distintos fabricantes.

---

# 2️⃣ ¿Qué es exactamente una MIB?

Una **MIB** es:

* Un archivo de texto
* Escrito en formato **ASN.1 (Abstract Syntax Notation One)**
* Con estructura jerárquica tipo árbol
* Que describe TODOS los objetos que pueden consultarse vía SNMP

⚠ Importante:

La MIB **NO contiene datos reales**.

No guarda métricas.
No guarda valores.

Solo describe:

* Qué se puede consultar
* Dónde está
* Qué tipo de dato devuelve
* Si puede modificarse o no

---

# 3️⃣ ¿Qué información contiene una MIB?

Cada objeto dentro de la MIB define:

* 📌 Un OID (dirección única)
* 🏷 Un nombre simbólico
* 🧾 Tipo de dato (Integer, String, Counter, etc.)
* 🔐 Permisos (read-only o read-write)
* 📖 Descripción textual

Es decir, responde a la pregunta:

> "¿Dónde está la información y cómo debo interpretarla?"

---

# 4️⃣ La Estructura en Forma de Árbol

La MIB organiza los objetos en una estructura jerárquica tipo árbol.

Visualmente sería algo así:

```
1
└── 3
    └── 6
        └── 1
            └── 2
                └── 1
                    └── 1
```

Cada nivel representa un nodo.

Cada nodo tiene un número.

La combinación completa forma un **OID**.

---

# 5️⃣ ¿Qué es un OID?

Un **OID (Object Identifier)** es la dirección exacta de un objeto dentro del árbol SNMP.

Ejemplo real:

```
1.3.6.1.2.1.1.1.0
```

Ese número representa una ruta dentro del árbol.

Es como una ruta de carpetas en un sistema operativo:

```
/home/juan/documentos/archivo.txt
```

Pero en formato numérico.

---

# 6️⃣ Cómo Leer un OID

Tomemos este ejemplo:

```
1.3.6.1.2.1.1.1.0
```

Cada número representa un nivel en la jerarquía.

Cuanto más largo el OID:

👉 Más específico es el objeto.

Muchos nodos intermedios no contienen datos reales.
Solo sirven como organización.

Los datos reales suelen estar en los nodos finales.

---

# 7️⃣ ¿Por Qué el OID es Tan Importante?

Cuando el cliente SNMP quiere información:

No dice:

"Dame la CPU"

Dice:

"Dame el valor del OID X"

El agente busca ese OID y devuelve el valor correspondiente.

Sin OID:

❌ No hay forma de saber qué dato pedir.

---

# 8️⃣ Relación entre MIB y OID

La relación es simple:

* La MIB define el mapa
* El OID es la dirección dentro del mapa
* El agente tiene los datos reales

Ejemplo mental:

MIB → Manual del edificio
OID → Número de departamento
Agente → Persona que vive ahí
Cliente → Quien toca el timbre

---

# 9️⃣ ASN.1 – ¿Por Qué es Relevante?

Las MIB están escritas en **ASN.1**, que es un estándar para definir estructuras de datos.

No necesitás dominar ASN.1 para hacer pentesting.

Pero es importante entender que:

* Es un formato estructurado
* Es estándar
* Permite que distintos fabricantes sean compatibles

---

# 🔟 Repositorios Útiles para Consultar OIDs

Podés buscar OIDs y su significado en:

* [https://oidref.com](https://oidref.com)
* [https://www.alvestrand.no/objectid/](https://www.alvestrand.no/objectid/)
* [https://oid-info.com](https://oid-info.com)

Estos sitios te permiten traducir un OID numérico en algo entendible.

---

# 1️⃣1️⃣ ¿Por Qué Esto es Clave en Pentesting?

Cuando hacés un:

```
snmpwalk -v2c -c public 10.10.10.10
```

El resultado que ves son OIDs con valores.

Si entendés la estructura:

✔ Podés identificar qué información es sensible
✔ Podés detectar usuarios
✔ Podés identificar interfaces
✔ Podés obtener datos del sistema operativo
✔ Podés descubrir información interna de red

Si no entendés OIDs y MIBs, el output parece ruido.

---


---

## 6. Versiones de SNMP

### 🔴 SNMPv1

* Primera versión
* Muy utilizada aún
* ❌ Sin autenticación real
* ❌ Sin cifrado
* Toda la información viaja en **texto plano**

Impacto en pentesting:

* Enumeración completa sin credenciales fuertes
* Intercepción trivial del tráfico

---

### 🟠 SNMPv2c

* Variante más común actualmente
* *c = community-based*
* Mismos problemas de seguridad que v1
* La **community string viaja en texto plano**

👉 Desde el punto de vista ofensivo:

* Equivalente práctico a SNMPv1

---

### 🟢 SNMPv3

* Autenticación por usuario
* Cifrado del tráfico
* Integridad de mensajes

Problema real:

* Mucha complejidad
* Migración costosa
* Poca adopción completa

Resultado:

> Muchas organizaciones **siguen expuestas** por SNMPv2c

---

## 7. Community Strings

Las **community strings** funcionan como contraseñas.

Ejemplos comunes:

* `public`
* `private`
* `public123`
* Nombre del host

Problemas frecuentes:

* Texto plano
* Reutilización
* Mal filtrado por IP

👉 Cada vez que se envían, **pueden ser interceptadas**.

---

## 8. Configuración por defecto del demonio SNMP

Archivo típico:

```bash
/etc/snmp/snmpd.conf
```

Ejemplo real:

```bash
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

Salida:

```
rocommunity public default -V systemonly
rwuser authPrivUser authpriv -V systemonly
```

Esto define:

* Qué OIDs son visibles
* Quién puede leer
* Quién puede escribir

Manual oficial:

* [https://www.net-snmp.org/docs/man/snmpd.conf.html](https://www.net-snmp.org/docs/man/snmpd.conf.html)

---

## 9. Configuraciones peligrosas

| Configuración               | Riesgo                                    |
| --------------------------- | ----------------------------------------- |
| `rwuser noauth`             | Acceso total al OID sin autenticación     |
| `rwcommunity <string> <IP>` | Proporciona acceso al árbol OID completo independientemente de dónde se enviaron las solicitudes. |
| `rwcommunity6`              | Igual riesgo en IPv6                      |

👉 Esto puede permitir:

* Modificar configuraciones
* Ejecutar acciones administrativas
* Facilitar RCE indirecto

---

## 10. Footprinting del servicio SNMP

### Herramientas principales:

* **snmpwalk** → Enumeración de OIDs
* **onesixtyone** → Fuerza bruta de community strings
* **braa** → Enumeración masiva de OIDs

---

## 11. Enumeración con snmpwalk

```bash
snmpwalk -v2c -c public 10.129.14.128
```

Información obtenible:

* Sistema operativo
* Versión del kernel
* Usuarios
* Servicios
* Paquetes instalados
* Procesos
* Variables de entorno

Ejemplo crítico:

```
Linux htb 5.11.0-34-generic
BOOT_IMAGE=/boot/vmlinuz...
python3_3.8.2-0ubuntu2
proftpd-basic
```

👉 Ya tenemos:

* OS fingerprint
* Software vulnerable potencial

---

## 12. Descubrimiento de community strings – onesixtyone

Instalación:

```bash
sudo apt install onesixtyone
```

Uso:

```bash
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

Wordlists:

* [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

Observación:

* Las community strings suelen seguir patrones
* En redes grandes, **la consistencia juega en contra del admin**

---

A menudo, cuando ciertas cadenas de comunidad se vinculan a direcciones IP específicas, se nombran con el nombre del host, e incluso se les añaden símbolos para dificultar su identificación. Sin embargo, si imaginamos una red extensa con más de 100 servidores diferentes administrados mediante SNMP, las etiquetas, en ese caso, seguirán un patrón. Por lo tanto, podemos usar diferentes reglas para deducirlas. Podemos usar la herramienta [crunch](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en) para crear listas de palabras personalizadas. 

---

## 13. Enumeración masiva de OIDs – braa

Instalación:

```bash
sudo apt install braa
```

Uso:

```bash
braa public@10.129.14.128:.1.3.6.*
```

Esto permite:

* Enumeración rápida
* Menos ruido que snmpwalk
* Identificar información crítica rápidamente


---

## 15. Conclusión

SNMP es uno de los servicios más **subestimados y poderosos** en la enumeración.

Un SNMP mal configurado puede revelar:

* Arquitectura completa
* Software instalado
* Usuarios
* Dependencias

Y todo esto **sin explotación activa**.



---



### Preguntas

`IP`: `10.129.226.159`

#### Enumere el servicio SNMP y obtenga la dirección de correo electrónico del administrador. Envíela como respuesta.


Hacemos un escaneo UDP rápido:
<img width="769" height="307" alt="image" src="https://github.com/user-attachments/assets/1e761e02-d23d-462e-938e-d463ec5e5ae0" />

Descubrimos es servicio SNMP en el puerto UDP 161.

Realizamos un escaneo de versiones:
<img width="1239" height="333" alt="image" src="https://github.com/user-attachments/assets/c11c6e2c-63e8-4870-b401-d4a5d3b047dd" />


Vemos SNMPv1 activo y la comunity string `public`.

SNMPv3 está instalado, pero SNMPv1/v2c sigue abierto, lo cual anula completamente la seguridad.

---

Utilizamos todos los scripts de nmap correspondientes a snmp:
<img width="1245" height="790" alt="image" src="https://github.com/user-attachments/assets/07c8b52c-2114-4a9e-baaf-efa59800a812" />
<img width="1103" height="841" alt="image" src="https://github.com/user-attachments/assets/4a136e3b-1841-4ab0-bcf5-bd57a74da62a" />
<img width="963" height="814" alt="image" src="https://github.com/user-attachments/assets/3551597a-1244-4630-b065-81391aefe77d" />
<img width="929" height="857" alt="image" src="https://github.com/user-attachments/assets/a2a68a3f-8e29-421e-b50f-47f73a6fa7de" />
<img width="960" height="848" alt="image" src="https://github.com/user-attachments/assets/e42e85fd-1349-416c-96e9-85e24c3d4102" />
<img width="1143" height="737" alt="image" src="https://github.com/user-attachments/assets/ce5552ba-bdcb-4731-bf0d-9192d6021b0f" />



---

Enumeramos con `snmpwalk`:
<img width="1383" height="808" alt="image" src="https://github.com/user-attachments/assets/f8898458-8952-48c7-bcd3-cbd3bc3b67b9" />

---


#### ¿Cuál es la versión personalizada del servidor SNMP?

<img width="1343" height="823" alt="image" src="https://github.com/user-attachments/assets/9979598d-cadd-48ae-b7aa-897ddf8de6d7" />

Versión personalizada:  InFreight SNMP v0.91


#### Enumere el script personalizado que se está ejecutando en el sistema y envíe su salida como respuesta.

<img width="1629" height="828" alt="image" src="https://github.com/user-attachments/assets/513865a6-7554-4959-be8c-20b407c7a3fc" />

`Script`: `/usr/share/flag.sh`

`Salida del script`: `HTB{5nMp_fl4g_uidhfljnsldiuhbfsdij44738b2u763g}
