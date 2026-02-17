# Fingerprinting

Fingerprinting se enfoca en extraer detalles técnicos sobre las tecnologías que impulsan un sitio web o aplicación web. De manera similar a cómo una huella digital identifica de forma única a una persona, las firmas digitales de servidores web, sistemas operativos y componentes de software pueden revelar información crítica sobre la infraestructura de un objetivo y sus posibles debilidades de seguridad.

Este conocimiento permite a un atacante adaptar sus ataques y explotar vulnerabilidades específicas de las tecnologías identificadas.

---

## ¿Por qué el Fingerprinting es clave en Web Recon?

### Targeted Attacks

Conocer las tecnologías específicas en uso permite enfocar los esfuerzos en exploits y vulnerabilidades que afectan directamente a esos sistemas. Esto incrementa significativamente las probabilidades de comprometer el objetivo.

### Identifying Misconfigurations

El fingerprinting puede exponer:

* Software desactualizado
* Configuraciones por defecto
* Headers inseguros
* Componentes mal configurados

Muchas de estas debilidades no son evidentes mediante otras técnicas de reconocimiento.

### Prioritising Targets

Cuando existen múltiples objetivos potenciales, el fingerprinting ayuda a priorizar aquellos que:

* Son más propensos a ser vulnerables
* Ejecutan software obsoleto
* Pueden contener información de mayor valor

### Building a Comprehensive Profile

Al combinar datos de fingerprinting con otros hallazgos de reconocimiento (DNS, CT logs, subdominios, OSINT), se construye una visión integral de la infraestructura del objetivo y su postura de seguridad.

---

# Fingerprinting Techniques

Existen varias técnicas utilizadas para identificar servidores web y tecnologías:

## Banner Grabbing

Consiste en analizar los banners que presentan los servidores web y otros servicios. Estos banners suelen revelar:

* Software del servidor
* Número de versión
* Sistema operativo

---

## Analysing HTTP Headers

Los headers HTTP transmitidos en cada request y response contienen gran cantidad de información.

* `Server`: suele indicar el software del servidor web.
* `X-Powered-By`: puede revelar lenguajes de scripting o frameworks.

---

## Probing for Specific Responses

Enviar solicitudes especialmente diseñadas puede provocar respuestas únicas que revelen tecnologías o versiones específicas.

Ejemplo:

* Mensajes de error característicos
* Comportamientos particulares ante métodos HTTP no comunes

---

## Analysing Page Content

El contenido HTML puede proporcionar pistas sobre tecnologías subyacentes:

* Comentarios en el código
* Estructura específica del CMS
* Archivos como `license.txt`
* Scripts cargados

---

# Herramientas de Fingerprinting

| Tool       | Description                                                             | Features                                                              |
| ---------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Wappalyzer | Extensión de navegador y servicio online para perfilar tecnologías web. | Identifica CMS, frameworks, herramientas de analítica y más.          |
| BuiltWith  | Perfilador tecnológico web con reportes detallados.                     | Ofrece planes gratuitos y pagos con distintos niveles de detalle.     |
| WhatWeb    | Herramienta CLI para fingerprinting web.                                | Usa una amplia base de firmas para identificar tecnologías.           |
| Nmap       | Escáner de red versátil.                                                | Permite fingerprinting de servicios y sistema operativo mediante NSE. |
| Netcraft   | Servicio de seguridad web.                                              | Reportes detallados sobre tecnología, hosting y postura de seguridad. |
| wafw00f    | Herramienta CLI para identificar WAFs.                                  | Detecta presencia y tipo de Web Application Firewall.                 |

---

# Fingerprinting inlanefreight.com

Aplicaremos técnicas manuales y automatizadas para identificar el stack tecnológico de `inlanefreight.com`.

---

## Banner Grabbing

```bash
curl -I inlanefreight.com
```

Resultado:

```
HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:07:44 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: https://inlanefreight.com/
Content-Type: text/html; charset=iso-8859-1
```

Observación:

* Servidor: Apache 2.4.41
* Sistema base: Ubuntu
* Redirección a HTTPS

---

```bash
curl -I https://inlanefreight.com
```

```
HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:12:12 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: https://www.inlanefreight.com/
Content-Type: text/html; charset=UTF-8
```

Observación:

* La redirección es gestionada por WordPress.

---

```bash
curl -I https://www.inlanefreight.com
```

```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>
```

Observación:

* Presencia de `wp-json` → Indicador claro de WordPress.

---

# Wafw00f

Antes de continuar con técnicas más agresivas, es importante detectar la presencia de un WAF.

Instalación:

```bash
pip3 install git+https://github.com/EnableSecurity/wafw00f
```

Ejecución:

```bash
wafw00f inlanefreight.com
```

Resultado:

```
The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
```

Conclusión:

* El sitio está protegido por Wordfence WAF.
* Puede filtrar o bloquear intentos de reconocimiento más agresivos.

---

# Nikto

Nikto es un escáner de servidores web que también realiza fingerprinting.

Instalación (si no está presente):

```bash
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```

Ejecución enfocada en identificación de software:

```bash
nikto -h inlanefreight.com -Tuning b
```

Hallazgos relevantes:

* Apache/2.4.41 (Ubuntu)
* WordPress detectado
* `/wp-login.php` identificado
* Archivo `/license.txt` expuesto
* Falta header Strict-Transport-Security
* Falta header X-Content-Type-Options
* Posible riesgo BREACH (Content-Encoding: deflate)
* Soporte IPv4 e IPv6
* Certificado emitido por Let's Encrypt

---

# Resumen del Stack Detectado

* Web Server: Apache 2.4.41 (Ubuntu)
* CMS: WordPress
* WAF: Wordfence
* Certificado TLS: Let's Encrypt
* Posibles debilidades: headers de seguridad faltantes, software potencialmente desactualizado

---

# Conclusión

El fingerprinting permite:

* Identificar con precisión el stack tecnológico del objetivo.
* Detectar configuraciones inseguras.
* Priorizar vectores de ataque.
* Reducir la superficie de incertidumbre antes de la explotación.

En una metodología profesional de pentesting, esta fase es crítica para transformar un reconocimiento genérico en un ataque dirigido y eficiente.
