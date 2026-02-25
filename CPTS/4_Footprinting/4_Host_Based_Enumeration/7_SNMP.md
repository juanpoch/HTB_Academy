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

# 🔐 SNMP – Versiones y Community Strings

---

# 1️⃣ ¿Por qué existen distintas versiones de SNMP?

SNMP nació en una época donde:

* Las redes eran pequeñas
* No existía tanta exposición a Internet
* La seguridad no era una prioridad como hoy

Con el tiempo, se descubrieron muchos problemas de seguridad.

En lugar de eliminar el protocolo, se fueron creando nuevas versiones para intentar corregir esos problemas.

Por eso hoy existen:

* SNMPv1
* SNMPv2c
* SNMPv3

Cada una mejora (en teoría) la anterior.

---

# 2️⃣ 🔴 SNMPv1 – La versión original

Es la primera versión del protocolo.

Características principales:

* Permite consultar información (GET)
* Permite modificar valores (SET)
* Permite recibir traps

⚠ Problemas graves de seguridad:

❌ No tiene autenticación real
❌ No tiene cifrado
❌ Todo viaja en texto plano

Eso significa que:

Si alguien captura el tráfico de red (por ejemplo con Wireshark), puede leer absolutamente todo.

Incluso puede ver la "contraseña" utilizada.

---

# 3️⃣ ¿Qué significa que viaja en texto plano?

Texto plano significa:

* No está cifrado
* No está protegido
* Se puede leer directamente

Es como mandar una contraseña por WhatsApp sin cifrado.

Cualquiera que intercepte el tráfico puede verla.

---

# 4️⃣ 🟠 SNMPv2c – Community-Based

SNMPv2 tuvo varias variantes.

La única que se mantiene en uso hoy es:

👉 SNMPv2c

La "c" significa **community-based**.

Esto significa que introduce el concepto de:

## Community String

Pero atención:

Aunque mejora algunas funciones técnicas del protocolo...

⚠ En términos de seguridad es prácticamente igual a v1.

¿Por qué?

Porque la community string también viaja en texto plano.

---

# 5️⃣ Entonces… ¿SNMPv2c es seguro?

No.

Es más práctico y eficiente que v1.

Pero desde el punto de vista de seguridad:

Es casi lo mismo.

Si alguien intercepta el tráfico:

Puede ver la community string.

Y si tiene la community correcta:

Puede enumerar completamente el dispositivo.

---

# 6️⃣ 🟢 SNMPv3 – La versión segura

SNMPv3 fue creado para solucionar los problemas de seguridad.

Introduce:

✔ Autenticación basada en usuario y contraseña
✔ Cifrado del tráfico
✔ Integridad de los mensajes

Esto significa que:

* No cualquiera puede consultar
* No cualquiera puede modificar
* El tráfico no puede leerse fácilmente

Ahora sí existe protección real.

---

# 7️⃣ ¿Entonces por qué no todos usan SNMPv3?

Porque:

* Es más complejo de configurar
* Requiere más parámetros
* Migrar redes grandes puede ser costoso
* Muchos dispositivos legacy no lo soportan completamente

Resultado práctico:

Muchas organizaciones siguen usando SNMPv2c.

Y ahí es donde aparece el problema.

---

# 8️⃣ Community Strings – Qué son realmente

Una **community string** es como una contraseña simple.

Funciona como un "token" que el cliente envía al agente.

Ejemplo clásico:

```
snmpwalk -v2c -c public 10.10.10.10
```

En ese ejemplo:

"public" es la community string.

Si es correcta:

El dispositivo responde.

Si es incorrecta:

No responde o devuelve error.

---

# 9️⃣ Tipos comunes de community strings

Las más comunes (por mala práctica):

* public
* private
* public123
* nombre_del_host

Muchos dispositivos vienen por defecto con:

* public → solo lectura
* private → lectura y escritura

Si no se cambian…

Quedan expuestos.

---

# 🔟 ¿Por qué son peligrosas?

Porque:

* Viajan en texto plano
* Pueden interceptarse
* Muchas veces no se cambian
* Se reutilizan en múltiples dispositivos

Si un atacante obtiene una community válida:

Puede:

✔ Enumerar usuarios
✔ Obtener interfaces
✔ Ver rutas internas
✔ Obtener versión del sistema
✔ Modificar configuraciones (si tiene permisos)

---

# 1️⃣1️⃣ Escenario de Ataque Real

Imaginemos:

Una empresa usa SNMPv2c con community "public".

Un atacante en la misma red ejecuta:

```
snmpwalk -v2c -c public 192.168.1.1
```

Si responde:

Acaba de exponer:

* Información del dispositivo
* Arquitectura interna
* Información de red

Todo sin credenciales fuertes.

---

---

# ⚙️ SNMP – Configuración del Demonio y Configuraciones Peligrosas (Explicado Desde Cero)

---

# 1️⃣ ¿Qué es el demonio SNMP?

En sistemas Linux, el servicio SNMP que responde a las consultas se llama:

```
snmpd
```

Es un **demonio (daemon)**, es decir:

👉 Un proceso que corre en segundo plano esperando consultas.

Este servicio es el que:

* Escucha en UDP 161
* Responde consultas SNMP
* Aplica reglas de acceso
* Define qué puede verse y qué puede modificarse

---

# 2️⃣ Archivo de configuración principal

El comportamiento del servicio se define en:

```bash
/etc/snmp/snmpd.conf
```

Este archivo controla:

* Qué IP escucha
* Qué OIDs son visibles
* Qué comunidades existen
* Qué usuarios pueden autenticarse
* Qué permisos tiene cada uno

---

# 3️⃣ Ejemplo real de configuración

Comando para ver solo líneas activas:

```bash
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

Salida:

```
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
master  agentx
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
```

---

# 4️⃣ Analizando línea por línea

### sysLocation

Define la ubicación física del dispositivo.

⚠ Puede revelar información sensible.

---

### sysContact

Persona responsable del sistema.

⚠ Puede revelar emails internos.

---

### agentaddress

```
agentaddress 127.0.0.1,[::1]
```

Define en qué IP escucha el demonio.

En este caso:

Solo localhost.

Si estuviera configurado como:

```
agentaddress udp:161
```

Escucharía en todas las interfaces.

---

### view systemonly

```
view systemonly included .1.3.6.1.2.1.1
```

Define qué parte del árbol OID puede verse.

Aquí solo permite consultar:

* Información del sistema

Esto limita el alcance.

---

### rocommunity public default -V systemonly

Significa:

* Community: public
* Permiso: read-only
* Desde: cualquier IP
* Vista: systemonly

Traducción práctica:

Cualquiera que conozca la community "public" puede consultar los OIDs definidos en la vista.

---

### rouser authPrivUser authpriv -V systemonly

Define un usuario SNMPv3 con:

* Autenticación
* Cifrado
* Acceso limitado a systemonly

Esto ya es una configuración más segura.

---

# 5️⃣ ¿Qué controla realmente snmpd.conf?

El archivo determina:

✔ Qué parte del árbol OID es accesible
✔ Quién puede leer
✔ Quién puede escribir
✔ Desde qué IP se permite acceso
✔ Si requiere autenticación

Es literalmente la política de seguridad de SNMP.

---

# 6️⃣ Configuraciones peligrosas

Algunas directivas pueden ser extremadamente riesgosas.

---

## 🔴 rwuser noauth

Significa:

* Usuario con permisos de escritura
* Sin autenticación
* Acceso al árbol completo

Impacto:

Un atacante podría modificar configuraciones sin autenticarse.

---

## 🔴 rwcommunity <string> <IP>

Ejemplo:

```
rwcommunity private 0.0.0.0/0
```

Significa:

* Community con permisos de lectura y escritura
* Desde cualquier IP
* Acceso completo al árbol OID

Impacto:

Acceso total si la community es conocida.

---

## 🔴 rwcommunity6

Misma lógica pero para IPv6.

Muchas veces se protege IPv4 pero se olvidan reglas en IPv6.

---

# 7️⃣ ¿Por qué esto es grave?

Con permisos de escritura (rw):

Un atacante podría:

✔ Modificar configuraciones de red
✔ Cambiar parámetros del sistema
✔ Activar o desactivar servicios
✔ Alterar rutas

En ciertos escenarios:

Puede facilitar ejecución remota indirecta.

---

# 8️⃣ Error común en administradores

Muchos piensan:

"SNMP solo es monitoreo"

Pero en realidad:

SNMP puede modificar el sistema si está mal configurado.

Y si además:

* Usa v2c
* Usa community débil
* Está expuesto a Internet

Se convierte en una superficie de ataque seria.

---

# 9️⃣ Recomendación práctica

Para entender bien SNMP:

Lo ideal es:

✔ Instalar una VM
✔ Configurar snmpd manualmente
✔ Probar distintas comunidades
✔ Hacer snmpwalk
✔ Cambiar permisos

Nada reemplaza verlo funcionando.

---

# 🔎 Conclusión

El archivo:

```
/etc/snmp/snmpd.conf
```

Es el corazón de la seguridad SNMP.

Si está mal configurado:

Puede permitir:

* Enumeración masiva
* Exposición de información interna
* Modificación remota
* Escalada de impacto

Por eso, en pentesting, cuando vemos SNMP abierto:

Siempre debemos preguntarnos:

👉 ¿Qué configuración está detrás?
👉 ¿Es solo lectura?
👉 ¿Tiene escritura?
👉 ¿Está restringido por IP?
👉 ¿Es v2c o v3?

Responder esas preguntas define el impacto real.


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
