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

# 7. Configuración DNS en BIND9

Archivos principales:

* named.conf.local
* named.conf.options
* named.conf.log

## Ejemplo de configuración local

```bash
root@bind9:~# cat /etc/bind/named.conf.local

zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

---

# 8. Zone Files

```bash
root@bind9:~# cat /etc/bind/db.domain.com

$ORIGIN domain.com
$TTL 86400
@ IN SOA dns1.domain.com. hostmaster.domain.com. (
        2001062501
        21600
        3600
        604800
        86400 )

    IN NS ns1.domain.com.
    IN NS ns2.domain.com.

    IN MX 10 mx.domain.com.

server1 IN A 10.129.14.5
ns1 IN A 10.129.14.2
www IN CNAME server1
```

---

# 9. Reverse Lookup Zone

```bash
root@bind9:~# cat /etc/bind/db.10.129.14

$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400

5 IN PTR server1.domain.com.
```

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
