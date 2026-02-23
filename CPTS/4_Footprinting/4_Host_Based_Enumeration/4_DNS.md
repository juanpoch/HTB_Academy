# DNS 

---

# 1. Introducción a DNS

El **Domain Name System (DNS)** es un componente esencial de Internet. Permite traducir nombres de dominio (por ejemplo, `www.hackthebox.com`) en direcciones IP que los sistemas pueden utilizar para comunicarse.

DNS no posee una base de datos centralizada. La información está distribuida en miles de servidores alrededor del mundo.

Podemos imaginarlo como una biblioteca global con múltiples guías telefónicas distribuidas.

---

# 2. Tipos de Servidores DNS

| Tipo de Servidor             | Descripción                                                                                                                                        |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| DNS Root Server              | Responsable de los Top-Level Domains (TLD). Son la última instancia cuando no se obtiene respuesta. Existen 13 root servers coordinados por [ICANN](https://www.icann.org/). |
| Authoritative Nameserver     | Tiene autoridad sobre una zona específica. Sus respuestas son vinculantes.                                                                         |
| Non-authoritative Nameserver | No es responsable directo de una zona; obtiene información mediante consultas recursivas o iterativas.                                             |
| Caching DNS Server           | Almacena respuestas durante un tiempo definido (TTL).                                                                                              |
| Forwarding Server            | Reenvía consultas a otro servidor DNS.                                                                                                             |
| Resolver                     | Realiza la resolución local en el sistema o router.                                                                                                |

---

# 3. Seguridad en DNS

DNS tradicionalmente no está cifrado.

Esto implica que:

* Proveedores de Internet pueden inspeccionar consultas.
* Dispositivos en la red local pueden espiar tráfico DNS.

Soluciones modernas:

* DNS over TLS (DoT)
* DNS over HTTPS (DoH)
* DNSCrypt

---

# 4. Jerarquía de Dominio

Estructura jerárquica:

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
