# 📡 Footprinting – SNMP (Simple Network Management Protocol)


---

## 1. Introducción a SNMP

El **Simple Network Management Protocol (SNMP)** fue creado para **monitorizar y administrar dispositivos de red**. No solo permite obtener métricas, sino también **modificar configuraciones remotamente**, lo que lo convierte en un objetivo extremadamente interesante durante la fase de enumeración.

Dispositivos típicos con SNMP habilitado:

* Routers
* Switches
* Firewalls
* Servidores
* Dispositivos IoT
* Impresoras
* Equipamiento industrial

👉 SNMP es, en esencia, un **protocolo de gestión y control**, no solo de lectura.

La versión actual es **SNMPv3**, que introduce seguridad real, pero en la práctica **SNMPv1 y SNMPv2c siguen estando ampliamente desplegados**.

---

## 2. Funcionamiento general de SNMP

SNMP funciona mediante un modelo **cliente ↔ agente**:

* El **agente SNMP** corre en el dispositivo gestionado.
* El **cliente SNMP** consulta o modifica información.

Puertos utilizados:

* **UDP 161** → consultas SNMP (get / set / walk)
* **UDP 162** → *SNMP traps*

### 🔔 SNMP Traps

A diferencia del modelo clásico cliente-servidor:

* El agente **puede enviar información sin ser solicitado**.
* Esto ocurre cuando sucede un evento específico (error, caída de servicio, umbral superado).

Desde el punto de vista ofensivo:

* Revelan arquitectura interna
* Pueden filtrar información crítica
* A veces están mal restringidos

---

## 3. Identificación de objetos SNMP

Para que SNMP funcione correctamente:

* Cada valor debe tener una **dirección única**.
* Esa dirección es conocida como **OID (Object Identifier)**.

Sin OIDs, SNMP no puede operar.

---

## 4. MIB – Management Information Base

La **MIB** es un componente fundamental de SNMP.

📄 ¿Qué es una MIB?

* Un archivo de texto
* Describe **qué información puede consultarse**
* Organiza los objetos en una **estructura jerárquica tipo árbol**

Características:

* Escrita en **ASN.1 (Abstract Syntax Notation One)**
* No contiene datos reales
* Define:

  * OID
  * Nombre
  * Tipo de dato
  * Permisos (read-only / read-write)
  * Descripción

👉 La MIB responde a la pregunta:

> *¿Dónde está la información y cómo se ve?*

Repositorio oficial de OIDs:

* [https://oidref.com](https://oidref.com)
* [https://www.alvestrand.no/objectid/](https://www.alvestrand.no/objectid/)

---

## 5. OID – Object Identifier

Un **OID** identifica de forma única un nodo en el árbol SNMP.

Ejemplo:

```
1.3.6.1.2.1.1.1.0
```

Características:

* Secuencia de números separados por puntos
* Cuanto más largo, más específico
* Muchos nodos solo sirven como referencia

Visualización del árbol:

* [https://oid-info.com](https://oid-info.com)

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

Versión personalizada:  InFreight SNMP v0.91
