# 🌐 Footprinting – Domain Information (OSINT Pasivo)


---

## 1. Introducción: Importancia de la Información de Dominio

En cualquier prueba de penetración, **la información de dominio es uno de los pilares centrales**. No se trata solamente de encontrar subdominios, sino de comprender **toda la presencia digital** de la organización: su infraestructura pública, proveedores externos, tecnologías utilizadas y dependencias.

El objetivo en esta etapa es **entender cómo funciona la empresa**, qué servicios ofrece y qué tecnologías son necesarias para brindarlos.

> Esta fase es **100% pasiva**: no realizamos escaneos directos hacia el objetivo.
> Nos comportamos como usuarios comunes, sin dejar huellas.

Las técnicas descritas aquí **no reemplazan al módulo OSINT: Corporate Recon**, pero representan una base sólida para un pentest externo.

---

## 2. Primer paso: Analizar el sitio web principal

Antes de usar herramientas externas, lo primero es visitar la **página principal** de la empresa y analizar:

* Textos de marketing → servicios ofrecidos
* Páginas técnicas → tecnologías mencionadas
* Productos → posibles stacks tecnológicos
* Formas de contacto → proveedores externos
* Cupones, newsletters → plataformas de terceros

Esto mezcla los **Principios de Enumeración 1 y 2**:

* *Ver lo visible*: servicios, nombres, secciones.
* *Inferir lo invisible*: ¿qué tecnologías permiten ofrecer ese servicio?

Ejemplo: una empresa menciona IoT, Data Science y Hosting → esto sugiere:

* APIs
* Brokers MQTT
* Bases de datos grandes
* Infraestructura cloud
* Contenedores
* Pipelines de CI/CD

Este análisis inicial nos permite inferir componentes técnicos **antes incluso de descubrir subdominios**.

---

## 3. Presencia en Internet: Punto de partida

Para un pentest **Black Box**, la empresa solo entrega un dominio o alcances limitados. Todo lo demás debemos descubrirlo.

Uno de los recursos más útiles es el **certificado SSL** del sitio principal.

Los certificados suelen incluir:

* Common Name (CN)
* Subject Alternative Names (SANs)

Estos SANs pueden contener **subdominios adicionales activos**.

Ejemplo típico:

<img width="848" height="244" alt="image" src="https://github.com/user-attachments/assets/e1687731-a35c-49a5-9568-da4101ffc775" />

<img width="836" height="427" alt="image" src="https://github.com/user-attachments/assets/51cec106-58d5-4faf-939f-f730e36ff60a" />



---

# 4. Uso de crt.sh – Certificate Transparency

➡️ **crt.sh**: [https://crt.sh](https://crt.sh)
➡️ Introducir dominio: `https://crt.sh/?q=inlanefreight.com`

**Certificate Transparency (RFC 6962)** obliga a que las autoridades certificadoras registren todos los certificados emitidos en logs públicos.

Esto permite:

* Detectar certificados fraudulentos
* Ver qué subdominios existen
* Descubrir servicios
* Identificar proveedores como Cloudflare, Google, AWS

Ejemplo real de crt.sh:

* matomo.inlanefreight.com
* smartfactory.inlanefreight.com
* shop.inlanefreight.com
* mails.inlanefreight.com

La búsqueda también revela los **Issuer**:

* Let's Encrypt
* Cloudflare Inc ECC CA-3
* DigiCert TLS RSA CA 2020

Estos proveedores nos indican:

* posibles tecnologías de hosting
* WAF o CDN (Cloudflare)
* certificados automatizados (Let's Encrypt)

---

## 5. Extraer resultados de crt.sh en JSON

```bash
curl -s https://crt.sh/?q=inlanefreight.com&output=json | jq .
```

Esto devuelve:

* *entry_timestamp*
* *not_before*
* *not_after*
* *serial_number*
* *name_value* (subdominio)
* *issuer*

---

## 6. Filtrar únicamente subdominios únicos

```bash
curl -s https://crt.sh/?q=inlanefreight.com&output=json | jq . |\
  grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 |\
  awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

Resultado esperado:

```
account.ttn.inlanefreight.com
blog.inlanefreight.com
bots.inlanefreight.com
console.ttn.inlanefreight.com
iot.inlanefreight.com
matomo.inlanefreight.com
smartfactory.inlanefreight.com
www.inlanefreight.com
...
```

Esta lista ya da un panorama muy claro del tipo de infraestructura.

---

# 7. Identificar servidores de la empresa (no terceros)

Debemos evitar atacar hosts no autorizados (ej. Google, AWS, Cloudflare).
Por eso filtramos solo los **A records que pertenecen a la organización**.

```bash
for i in $(cat subdomainlist); do
    host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4
done
```

Ejemplo:

```
blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
```

---

# 8. Integración con Shodan

➡️ [https://www.shodan.io](https://www.shodan.io)

Shodan permite obtener información detallada sobre:

* Puertos abiertos
* Versiones de servicios
* Certificados
* Geolocalización
* Organización
* Fingerprints de servidores

Procesar IPs:

```bash
for i in $(cat subdomainlist); do
  host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt
done
```

Consultar cada IP:

```bash
for i in $(cat ip-addresses.txt); do
  shodan host $i
done
```

Resultados posibles:

```
Ports:
 80/tcp nginx
 443/tcp nginx
---
22/tcp OpenSSH 7.6p1
80/tcp nginx
443/tcp nginx TLS1.2
---
25/tcp (SMTP)
53/tcp
80/tcp Apache
443/tcp Apache
```

Esto nos da una **vista rápida del ataque superficial** de cada host.

Recordar IP importante:

```
10.129.127.22 → matomo.inlanefreight.com
```

---

# 9. DNS Enumeration – Registros ANY

DNS puede revelar información valiosísima:

```bash
dig any inlanefreight.com
```

Esto revela:

* **A records**: Direcciones IP
* **MX records**: Servicios de correo (Google, Outlook, etc.)
* **NS records**: Hosting del dominio (INWX)
* **TXT records**: Validaciones y configuraciones
* **SOA record**: Servidor autoritativo

Ejemplo de TXT reveladores:

```
atlassian-domain-verification=...
google-site-verification=...
logmein-verification-code=...
v=spf1 include:mailgun.org include:_spf.google.com ...
```

---

# 10. Análisis de Proveedores Identificados

Los TXT permiten descubrir **servicios utilizados internamente**:

### ✔ Atlassian

[https://www.atlassian.com/](https://www.atlassian.com/)

* Jira
* Confluence
* Bitbucket

Indica presencia de pipelines, repositorios y posibles fugas.

### ✔ Gmail / Google Workspace

[https://workspace.google.com/](https://workspace.google.com/)

* Gmail corporativo
* Google Drive → posibilidad de archivos públicos

### ✔ LogMeIn

[https://www.logmein.com/](https://www.logmein.com/)

* Control remoto centralizado
* Alto riesgo si comprometen credenciales

### ✔ Mailgun

[https://www.mailgun.com/](https://www.mailgun.com/)

* APIs de email, webhooks → posibles vectores SSRF, IDOR, RCE

### ✔ Outlook / Office 365

[https://www.microsoft.com/es-ar/microsoft-365](https://www.microsoft.com/es-ar/microsoft-365)

* OneDrive
* Azure Blob / File Storage (SMB en la nube)

### ✔ INWX – Hosting DNS

[https://www.inwx.com/](https://www.inwx.com/)

* Gestión de dominios
* Usuario/ID revelado parcialmente en TXT

### ✔ AWS (detectado indirectamente por subdominio s3-website)

[https://aws.amazon.com/s3/](https://aws.amazon.com/s3/)

* Buckets S3 → revisar exposición pública

Cada proveedor añade nuevos ángulos para investigación.

---

# 11. Resumen de inteligencia recolectada

De una simple consulta DNS y crt.sh se identificaron:

### Información técnica interna:

* Subdominios activos
* IP ranges internos
* Servicios web y correo
* APIs relacionadas (Mailgun)

### Plataformas externas:

* Atlassian
* Google Workspace
* LogMeIn
* Office 365
* INWX
* AWS S3

### Potenciales vectores:

* Repositorios accesibles
* Documentación interna
* Webhooks expuestos
* Buckets S3 mal configurados
* Interfaces de admins de terceros

---

# 12. Conclusión

La recopilación pasiva de información ya permite construir un **mapa completo de la superficie de ataque**, sin enviar un solo paquete al servidor objetivo.

Este lienzo cubre:

* técnicas avanzadas de OSINT pasivo
* análisis de certificados (crt.sh)
* inferencia de proveedores
* extracción masiva de subdominios
* enriquecimiento de datos con Shodan y DNS

Este proceso sienta las bases para la siguiente etapa: **Gateway & Accessible Services Enumeration**.

---
