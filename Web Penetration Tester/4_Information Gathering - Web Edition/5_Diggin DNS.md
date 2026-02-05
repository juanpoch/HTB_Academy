# Digging DNS

## Introducción

Una vez comprendidos los **fundamentos de DNS** y los distintos **tipos de registros**, el siguiente paso natural es llevar ese conocimiento a la práctica. En esta sección se exploran las **herramientas y técnicas** más utilizadas para aprovechar DNS durante el **Web Reconnaissance**.

El objetivo es aprender a **consultar servidores DNS**, interpretar correctamente las respuestas y extraer información útil que permita ampliar la superficie de ataque del objetivo.

---

## Herramientas de DNS para Reconocimiento

El reconocimiento DNS se apoya en herramientas especializadas que permiten consultar servidores DNS y recolectar información relevante.

### Herramientas más utilizadas

| Herramienta              | Características clave                                                                                                         | Casos de uso                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **dig**                  | Herramienta versátil que soporta múltiples tipos de consultas (A, MX, NS, TXT, etc.) y ofrece salida detallada y configurable | Consultas manuales, análisis profundo de registros DNS, troubleshooting, transferencias de zona (si están permitidas) |
| **nslookup**             | Herramienta simple para consultas básicas                                                                                     | Consultas rápidas de resolución, A, AAAA y MX                                                                         |
| **host**                 | Salida concisa y directa                                                                                                      | Verificaciones rápidas de registros A, AAAA y MX                                                                      |
| **dnsenum**              | Enumeración DNS automatizada, diccionarios, brute force, transferencias de zona                                               | Descubrimiento eficiente de subdominios                                                                               |
| **fierce**               | Enumeración DNS con búsqueda recursiva y detección de wildcards                                                               | Identificación de subdominios y activos asociados                                                                     |
| **dnsrecon**             | Combina múltiples técnicas de enumeración y soporta varios formatos de salida                                                 | Enumeración DNS completa y recolección estructurada                                                                   |
| **theHarvester**         | Herramienta OSINT que incluye información DNS                                                                                 | Obtención de emails, dominios y datos asociados                                                                       |
| **Servicios DNS online** | Interfaces web amigables                                                                                                      | Consultas rápidas cuando no se dispone de CLI                                                                         |

---

## dig — Domain Information Groper

El comando **dig** (*Domain Information Groper*) es una de las herramientas más potentes para consultas DNS. Su flexibilidad y nivel de detalle lo convierten en una opción estándar en tareas de reconocimiento web.

---

## Comandos comunes con dig

| Comando                         | Descripción                                                         |
| ------------------------------- | ------------------------------------------------------------------- |
| `dig domain.com`                | Consulta por defecto (registro A)                                   |
| `dig domain.com A`              | Obtiene la dirección IPv4                                           |
| `dig domain.com AAAA`           | Obtiene la dirección IPv6                                           |
| `dig domain.com MX`             | Obtiene servidores de correo                                        |
| `dig domain.com NS`             | Identifica servidores autoritativos                                 |
| `dig domain.com TXT`            | Recupera registros TXT                                              |
| `dig domain.com CNAME`          | Consulta registros CNAME                                            |
| `dig domain.com SOA`            | Obtiene el registro SOA                                             |
| `dig @1.1.1.1 domain.com`       | Consulta un servidor DNS específico                                 |
| `dig +trace domain.com`         | Muestra el camino completo de resolución                            |
| `dig -x 192.168.1.1`            | Resolución inversa (PTR)                                            |
| `dig +short domain.com`         | Salida mínima, solo la respuesta                                    |
| `dig +noall +answer domain.com` | Muestra solo la sección ANSWER                                      |
| `dig domain.com ANY`            | Intenta obtener todos los registros (muchos servidores lo bloquean) |

> ⚠️ **Advertencia:** consultas excesivas pueden ser detectadas o bloqueadas. Siempre respetar límites y actuar únicamente con autorización.

---

## Ejemplo práctico: consulta con dig

Comando ejecutado:

```bash
dig google.com
```

Salida (fragmento):

```text
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142
```

> 📸 **Acá pegá la captura del comando dig ejecutado**.

---

## Análisis de la salida de dig

### Header

* **opcode: QUERY** → Tipo de operación
* **status: NOERROR** → Consulta exitosa
* **id: 16449** → Identificador único de la consulta

#### Flags

* **qr**: respuesta a una consulta
* **rd**: recursion desired (recursión solicitada)
* **ad**: authentic data (datos considerados auténticos)

La advertencia:

```text
recursion requested but not available
```

indica que el servidor consultado no soporta recursión.

---

### Question Section

```text
;google.com. IN A
```

Pregunta realizada: *¿Cuál es la dirección IPv4 (registro A) de google.com?*

---

### Answer Section

```text
google.com. 0 IN A 142.251.47.142
```

* **IP asociada:** 142.251.47.142
* **TTL:** 0 (tiempo de cacheo)

---

### Footer

* **Query time:** tiempo de respuesta
* **SERVER:** servidor DNS que respondió
* **WHEN:** fecha y hora de la consulta
* **MSG SIZE:** tamaño del mensaje DNS

---

## OPT Pseudosection y EDNS

En algunas consultas puede aparecer una **OPT Pseudosection**, asociada a **EDNS (Extension Mechanisms for DNS)**.

EDNS permite:

* Mensajes DNS más grandes
* Soporte para DNSSEC
* Extensiones modernas del protocolo DNS

---

## Salida simplificada con +short

Si solo interesa la respuesta final:

```bash
dig +short hackthebox.com
```

Salida:

```text
104.18.20.126
104.18.21.126
```

Este formato es ideal para **scripts**, **automatización** o filtrado rápido de información.

---

## Conclusión

El uso de **dig** es fundamental para cualquier tarea de reconocimiento DNS. Permite entender no solo *qué* responde DNS, sino también *cómo* y *desde dónde*, aportando contexto crítico para:

* Enumeración de activos
* Análisis de infraestructura
* Identificación de configuraciones débiles

Dominar dig marca una diferencia clara entre un reconocimiento superficial y uno **profesional y preciso**.
