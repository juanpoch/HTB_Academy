# DNS 

---

# 1. Introducción a DNS

El **Domain Name System (DNS)** es un componente esencial de Internet. Permite traducir nombres de dominio (por ejemplo, `www.hackthebox.com`) en direcciones IP que los sistemas pueden utilizar para comunicarse.

DNS no posee una base de datos centralizada. La información está distribuida en miles de servidores alrededor del mundo.

Podemos imaginarlo como una biblioteca global con múltiples guías telefónicas distribuidas.

---

# 2. Tipos de Servidores DNS

| Tipo de Servidor | Descripción |
|------------------|------------|
| **DNS Root Server** | Son la capa más alta de la jerarquía DNS. No resuelven directamente dominios completos, sino que indican qué servidores son responsables de cada Top-Level Domain (TLD) como `.com`, `.net` o `.org`. Existen 13 conjuntos de root servers a nivel mundial, coordinados por [ICANN](https://www.icann.org/), distribuidos globalmente para garantizar redundancia y disponibilidad. |
| **Authoritative Nameserver** | Tiene autoridad sobre una zona específica (por ejemplo, `empresa.com`). Contiene los registros oficiales (A, MX, NS, etc.) y sus respuestas son definitivas. Si este servidor responde, la información se considera válida y confiable para esa zona. |
| **Non-authoritative Nameserver** | No posee la zona original, sino que responde basándose en información obtenida previamente de otros servidores mediante consultas recursivas o iterativas. Sus respuestas no son la fuente original, pero pueden ser correctas si están actualizadas. |
| **Caching DNS Server** | Almacena temporalmente respuestas DNS obtenidas de otros servidores para acelerar futuras consultas. El tiempo que conserva esa información está determinado por el valor TTL (Time To Live) definido en los registros. Reduce latencia y carga en servidores autoritativos. |
| **Forwarding Server** | No resuelve consultas directamente, sino que reenvía todas las peticiones DNS a otro servidor específico (por ejemplo, el DNS del ISP o un servidor interno). Se utiliza comúnmente en redes corporativas para centralizar el control del tráfico DNS. |
| **Resolver** | Es el componente que inicia la consulta DNS desde el sistema del usuario o router. Puede ser parte del sistema operativo o un servicio local. Su función es contactar a los servidores DNS adecuados hasta obtener la respuesta final que permita traducir un dominio en una dirección IP. |


<img width="948" height="605" alt="image" src="https://github.com/user-attachments/assets/7493524a-ea23-48e6-a9ff-6162849bdf58" />

---

# 3. Seguridad en DNS


---

## 1. DNS y la Falta de Cifrado

El protocolo DNS tradicional fue diseñado en una época en la que la seguridad y la privacidad no eran prioridades centrales en Internet. Por defecto, las consultas DNS viajan en texto plano a través de la red (normalmente por el puerto 53 UDP/TCP).

Esto implica que:

* Cualquier dispositivo dentro de la misma red local (WLAN) puede interceptar las consultas.
* El proveedor de Internet (ISP) puede registrar y analizar todos los dominios que visitamos.
* Un atacante con capacidad de "Man-in-the-Middle" puede espiar o incluso manipular respuestas DNS.

En otras palabras, aunque el contenido de una página web esté protegido con HTTPS, la consulta DNS previa puede revelar qué dominio estamos intentando visitar.

---

## 2. Riesgos Asociados

La falta de cifrado en DNS puede provocar:

* Pérdida de privacidad (historial de navegación expuesto).
* Ataques de DNS Spoofing o DNS Poisoning.
* Redirección maliciosa hacia servidores controlados por atacantes.
* Enumeración pasiva de infraestructura interna en redes corporativas.

Por esta razón, el DNS tradicional representa un punto crítico desde el punto de vista de seguridad.

---

## 3. Mecanismos Modernos de Cifrado DNS

Para mitigar estos riesgos, se desarrollaron soluciones que encapsulan o cifran las consultas DNS:

### DNS over TLS (DoT)

* Utiliza el protocolo TLS para cifrar el tráfico DNS.
* Opera normalmente sobre el puerto 853.
* Establece un canal seguro entre el cliente y el servidor DNS.
* Ofrece confidencialidad y protección contra manipulación.

### DNS over HTTPS (DoH)

* Envía consultas DNS a través de HTTPS.
* Utiliza el puerto 443.
* Se mezcla con el tráfico web normal, lo que dificulta su bloqueo o inspección.
* Es ampliamente utilizado por navegadores modernos.

### DNSCrypt

* Protocolo independiente que cifra y autentica el tráfico DNS.
* Protege contra ataques de tipo "Man-in-the-Middle".
* No depende directamente de TLS, aunque cumple un propósito similar.

Estas tecnologías mejoran significativamente la privacidad del usuario y reducen la posibilidad de manipulación del tráfico DNS.

---

## 4. DNS Como Fuente de Información Estratégica

DNS no solo traduce nombres de dominio a direcciones IP. También almacena información clave sobre la infraestructura asociada a un dominio.

Una simple consulta DNS puede revelar:

* Qué servidores gestionan el correo electrónico (registros MX).
* Cuáles son los nameservers responsables (registros NS).
* Qué subdominios existen (registros A, AAAA, CNAME).
* Información de validación y políticas de correo (registros TXT como SPF o DMARC).

Desde la perspectiva de pentesting y reconocimiento (recon), DNS es una fuente extremadamente valiosa de información pasiva.

Por ejemplo:

* Identificar el servidor de correo puede revelar proveedores externos.
* Los nameservers pueden indicar si la infraestructura está alojada en AWS, Azure u otro proveedor.
* Los registros TXT pueden exponer integraciones con servicios externos.

En consecuencia, DNS no es solo un sistema de resolución de nombres, sino también un mapa indirecto de la arquitectura tecnológica de una organización.





---

# 4. Jerarquía de Dominio

Estructura jerárquica como marca la imagen:

```
Root (.)
 ├── TLD (.com, .net, .org, .io, etc.)
 │     └── Segundo Nivel (inlanefreight.com)
 │            ├── www.inlanefreight.com
 │            ├── dev.inlanefreight.com
 │            └── mail.inlanefreight.com
 │                   └── WS01.dev.inlanefreight.com
```

---

# 5. Tipos de Registros DNS

| Registro | Descripción                                       |
| -------- | ------------------------------------------------- |
| A        | Devuelve dirección IPv4.                          |
| AAAA     | Devuelve dirección IPv6.                          |
| MX       | Servidores de correo responsables.                |
| NS       | Nameservers del dominio.                          |
| TXT      | Información adicional (SPF, DMARC, validaciones). |
| CNAME    | Alias hacia otro dominio.                         |
| PTR      | Resolución inversa (IP → dominio).                |
| SOA      | Información administrativa de la zona.            |

---

# 6. Consulta SOA

```bash
CyberWolfSec@htb[/htb]$ dig soa www.inlanefreight.com

; <<>> DiG 9.16.27-Debian <<>> soa www.inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15876
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400
```

El correo administrativo se interpreta como:

```
awsdns-hostmaster@amazon.com
```

---



# 7. DNS – Configuración por Defecto en BIND9

---

# 1. Introducción

Los servidores DNS pueden configurarse de múltiples formas dependiendo del entorno (corporativo, ISP, laboratorio, nube, etc.). Sin embargo, la mayoría de implementaciones en sistemas Linux utilizan **[BIND9 (Berkeley Internet Name Domain)](https://www.isc.org/bind/)** como servidor DNS.

Desde el punto de vista administrativo, entender la configuración por defecto es fundamental para:

* Comprender cómo se resuelven las consultas.
* Identificar posibles malas configuraciones.
* Detectar vulnerabilidades explotables (como zone transfers no restringidos).

Todos los servidores DNS trabajan principalmente con **tres tipos de archivos de configuración**:

1. Archivos de configuración local.
2. Archivos de zona (zone files).
3. Archivos de resolución inversa.

---

# 2. Archivos de Configuración Local

En BIND9, el archivo principal es:

```
/etc/bind/named.conf
```

Este archivo generalmente incluye otros archivos secundarios que organizan la configuración:

* `named.conf.local`
* `named.conf.options`
* `named.conf.log`

## División lógica de named.conf

La configuración se divide en dos grandes bloques:

### 1️⃣ Opciones Globales

Afectan el comportamiento general del servidor DNS.

Ejemplos típicos:

* Control de recursión.
* Interfaces donde escucha el servidor.
* Permisos de consulta.
* Configuración de logging.

Estas opciones impactan a todas las zonas configuradas.

---

### 2️⃣ Declaraciones de Zona

Definen qué dominios administra el servidor.

Cada zona especifica:

* Tipo (master, slave, forward).
* Archivo donde se almacenan los registros.
* Restricciones de transferencia.

Si una opción se define tanto globalmente como dentro de una zona, **la configuración específica de la zona tiene prioridad**.

---

# 3. Ejemplo de Configuración Local

```bash
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

---

# 4. Análisis Detallado del Ejemplo

### zone "domain.com"

Define que el servidor es responsable de la zona `domain.com`.

---

### type master

Indica que este servidor es el **servidor primario (master)** para esa zona.

* Aquí se realizan las modificaciones.
* Es la fuente original de los datos.
* Los servidores secundarios (slaves) sincronizan desde este.

---

### file "/etc/bind/db.domain.com"

Especifica el archivo donde están almacenados los registros DNS de esa zona.

Este archivo contiene:

* SOA
* NS
* A
* MX
* CNAME
* TXT

Es el "libro telefónico" del dominio.

---

### allow-update { key rndc-key; };

Permite actualizaciones dinámicas autenticadas mediante una clave (`rndc-key`).

Esto es importante en entornos donde:

* Servidores DHCP actualizan automáticamente registros DNS.
* Se utilizan entornos Active Directory.

Si esta directiva está mal configurada, podría permitir modificaciones no autorizadas en la zona.

---

# 5. Relación con los RFC

BIND9 implementa estándares definidos en múltiples RFC relacionados con DNS.

La configuración permite adaptar el servidor a:

* Arquitecturas distribuidas.
* Balanceo de carga.
* Alta disponibilidad.
* Delegación de subzonas.

---



# DNS – Zone Files, Reverse Lookup y Configuraciones Peligrosas

---

# 1. ¿Qué es un Zone File?

Un **zone file** es un archivo de texto que describe completamente una zona DNS utilizando el formato estándar de **BIND**.

En términos simples, una zona es un punto de delegación dentro del árbol jerárquico DNS. Es decir, representa la porción del espacio de nombres sobre la cual un servidor tiene autoridad.

El formato BIND es el estándar de facto en la industria y es utilizado por la mayoría de los servidores DNS.

Un zone file debe contener obligatoriamente:

* Exactamente **un registro SOA (Start of Authority)**.
* Al menos **un registro NS (Name Server)**.

El registro SOA generalmente aparece al comienzo del archivo y define información crítica sobre la administración y sincronización de la zona.

⚠️ Un error de sintaxis en un zone file puede provocar que toda la zona sea considerada inválida. En ese caso, el servidor DNS responderá con errores `SERVFAIL`, como si la zona no existiera.

---

# 2. Zone File – Resolución Directa (Forward Lookup)

Aquí se definen todos los registros directos:

```
Dominio / Hostname → Dirección IP
```

En términos prácticos, este archivo es el "directorio telefónico" que el servidor consulta para saber qué IP corresponde a cada dominio.

## Ejemplo Completo

```bash
root@bind9:~# cat /etc/bind/db.domain.com

;
; BIND forward data file
;
$ORIGIN domain.com
$TTL 86400

@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh (6h)
                    3600       ; retry (1h)
                    604800     ; expire (1w)
                    86400 )    ; minimum TTL (1d)

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

      IN     MX     10     mx.domain.com.
      IN     MX     20     mx2.domain.com.

             IN     A       10.129.14.5

server1      IN     A       10.129.14.5
server2      IN     A       10.129.14.7
ns1          IN     A       10.129.14.2
ns2          IN     A       10.129.14.3

ftp          IN     CNAME   server1
mx           IN     CNAME   server1
mx2          IN     CNAME   server2
www          IN     CNAME   server2
```

---

# 3. Análisis del Registro SOA

El SOA contiene parámetros clave:

* **Serial**: número de versión de la zona. Si aumenta, los servidores secundarios sincronizan.
* **Refresh**: cada cuánto el slave consulta al master.
* **Retry**: tiempo de reintento si falla la consulta.
* **Expire**: cuándo el slave deja de confiar en los datos.
* **Minimum TTL**: tiempo mínimo de cacheo.

Este registro controla el mecanismo de replicación entre servidores master y slave.

---

# 4. Reverse Lookup Zone (Resolución Inversa)

Para que una IP pueda resolverse a un FQDN (Fully Qualified Domain Name), se necesita un archivo de resolución inversa.

Aquí la relación es:

```
Dirección IP → Dominio (PTR record)
```

## Ejemplo Completo

```bash
root@bind9:~# cat /etc/bind/db.10.129.14

;
; BIND reverse data file
;
$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400

@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501
                    21600
                    3600
                    604800
                    86400 )

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

5    IN     PTR    server1.domain.com.
7    IN     PTR    server2.domain.com.
```

En este caso:

* 10.129.14.5 → server1.domain.com
* 10.129.14.7 → server2.domain.com

Los registros PTR son fundamentales para:

* Validaciones de correo electrónico.
* Análisis forense.
* Identificación de infraestructura.

---

# 5. Configuraciones Peligrosas en BIND

DNS puede volverse altamente vulnerable si ciertas directivas no están correctamente restringidas.

| Opción          | Riesgo                                                                                                                 |
| --------------- | ---------------------------------------------------------------------------------------------------------------------- |
| allow-query     | Permite definir qué hosts pueden consultar el servidor. Si está en "any", cualquiera puede enumerar registros.         |
| allow-recursion | Si está habilitado públicamente, puede convertir al servidor en un open resolver (usable en ataques de amplificación). |
| allow-transfer  | Si permite transferencias sin restricción, un atacante puede obtener el zone file completo (AXFR).                     |
| zone-statistics | Puede revelar información estructural adicional de las zonas.                                                          |

---

# 6. Riesgo Operativo Real

En entornos reales, los administradores a veces relajan configuraciones por motivos de funcionalidad:

* Permitir transferencias para facilitar sincronización.
* Habilitar recursión para pruebas.
* Exponer estadísticas para monitoreo.

Cuando la funcionalidad tiene prioridad sobre la seguridad, pueden generarse:

* Filtraciones de infraestructura interna.
* Enumeración completa de subdominios.
* Exposición de IP privadas.
* Superficie ampliada para ataques dirigidos.









---

# 10. Footprinting DNS

## NS Query

```bash
CyberWolfSec@htb[/htb]$ dig ns inlanefreight.htb @10.129.14.128

;; ANSWER SECTION:
inlanefreight.htb. 604800 IN NS ns.inlanefreight.htb.
ns.inlanefreight.htb. 604800 IN A 10.129.34.136
```

---

## Version Query

```bash
CyberWolfSec@htb[/htb]$ dig CH TXT version.bind 10.129.120.85

;; ANSWER SECTION:
version.bind. 0 CH TXT "9.10.6-P1"
```

---

## ANY Query

```bash
CyberWolfSec@htb[/htb]$ dig any inlanefreight.htb @10.129.14.128

;; ANSWER SECTION:
inlanefreight.htb. 604800 IN TXT "v=spf1 include:mailgun.org ..."
inlanefreight.htb. 604800 IN NS ns.inlanefreight.htb.
```

---

# 11. Zone Transfer (AXFR)

```bash
CyberWolfSec@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128

inlanefreight.htb. 604800 IN SOA ...
app.inlanefreight.htb. 604800 IN A 10.129.18.15
internal.inlanefreight.htb. 604800 IN A 10.129.1.6
mail1.inlanefreight.htb. 604800 IN A 10.129.18.201
```

Si allow-transfer está mal configurado, puede revelarse:

* Infraestructura interna
* IP privadas
* Controladores de dominio
* Servidores VPN

---

# 12. Subdomain Brute Force

```bash
CyberWolfSec@htb[/htb]$ for sub in $(cat subdomains.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v 'SOA';done

ns.inlanefreight.htb. 604800 IN A 10.129.34.136
mail1.inlanefreight.htb. 604800 IN A 10.129.18.201
app.inlanefreight.htb. 604800 IN A 10.129.18.15
```

---

## Uso de DNSenum

```bash
CyberWolfSec@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f wordlist.txt inlanefreight.htb

ns.inlanefreight.htb. 604800 IN A 10.129.34.136
mail1.inlanefreight.htb. 604800 IN A 10.129.18.201
app.inlanefreight.htb. 604800 IN A 10.129.18.15
```

---

# 13. Configuraciones Peligrosas

| Opción          | Riesgo                                       |
| --------------- | -------------------------------------------- |
| allow-query     | Permite que cualquiera consulte el servidor. |
| allow-recursion | Puede convertirlo en open resolver.          |
| allow-transfer  | Permite zone transfers no autorizados.       |
| zone-statistics | Puede revelar información sensible.          |

---

# 14. Conclusiones Técnicas

✔ Enumerar NS
✔ Consultar versión
✔ Probar ANY
✔ Intentar AXFR
✔ Brute-force subdominios
✔ Revisar allow-transfer

DNS mal configurado puede revelar toda la infraestructura interna sin necesidad de explotación activa.

---

FIN DEL LIENZO
