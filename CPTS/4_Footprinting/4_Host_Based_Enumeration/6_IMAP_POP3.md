# IMAP / POP3 – Footprinting y Comprensión Profunda del Protocolo

---

## 1. Introducción

Los protocolos **IMAP (Internet Message Access Protocol)** y **POP3 (Post Office Protocol v3)** son utilizados para la **recepción y gestión de correos electrónicos** desde un servidor de correo.

Mientras que SMTP se utiliza para el envío de emails, IMAP y POP3 permiten acceder a los mensajes almacenados en el servidor.

En un contexto de **pentesting y footprinting**, estos servicios son extremadamente interesantes porque:

* Pueden revelar usuarios válidos.
* Exponen información organizacional (certificados, dominios internos, nombres reales).
* Permiten validación de credenciales.
* En configuraciones débiles, pueden permitir lectura completa del buzón.

---

# 2. IMAP – Explicación Técnica Profunda

## 2.1 ¿Qué es IMAP?

IMAP es un protocolo cliente-servidor que permite:

* Gestionar correos directamente en el servidor.
* Mantener sincronización entre múltiples clientes.
* Crear estructuras jerárquicas de carpetas.
* Acceder a múltiples buzones durante una misma sesión.

### Características clave:

* Protocolo **basado en texto (ASCII)**.
* Permite múltiples comandos en pipeline.
* Utiliza identificadores por comando (ej: A001, A002).
* Mantiene los emails en el servidor.
* Permite acceso simultáneo de múltiples clientes.

IMAP actúa como una especie de "filesystem remoto" para el correo electrónico.

---

## 2.2 Puerto por defecto

* 143 → IMAP sin cifrar
* 993 → IMAPS (IMAP sobre SSL/TLS)

Sin cifrado, transmite:

* Usuario
* Contraseña
* Emails
* Comandos

Todo en texto plano.

---

## 2.3 Flujo de conexión IMAP

1. Cliente conecta al puerto 143 o 993.
2. Servidor envía banner.
3. Cliente solicita CAPABILITY.
4. Cliente se autentica.
5. Selecciona mailbox.
6. Puede listar, leer, borrar o mover emails.

---

# 3. POP3 – Explicación Técnica Profunda

## 3.1 ¿Qué es POP3?

POP3 es mucho más simple que IMAP.

Permite únicamente:

* Listar correos
* Descargar correos
* Borrar correos

No soporta:

* Carpetas jerárquicas
* Sincronización multi-cliente avanzada
* Gestión estructurada del buzón

POP3 normalmente descarga el correo y lo elimina del servidor.

---

## 3.2 Puertos por defecto

* 110 → POP3 sin cifrar
* 995 → POP3S (SSL/TLS)

---

# 4. Diferencias Clave IMAP vs POP3

| Característica                | IMAP | POP3             |
| ----------------------------- | ---- | ---------------- |
| Sincronización multi-cliente  | Sí   | No               |
| Carpetas                      | Sí   | No               |
| Emails permanecen en servidor | Sí   | No (por defecto) |
| Gestión avanzada              | Sí   | No               |
| Complejidad                   | Alta | Baja             |

---

# 5. Comandos IMAP Importantes

| Comando                 | Función           |
| ----------------------- | ----------------- |
| LOGIN username password | Autenticación     |
| LIST "" *               | Lista directorios |
| SELECT INBOX            | Selecciona buzón  |
| FETCH <ID> all          | Obtiene email     |
| LOGOUT                  | Cierra conexión   |

---

# 6. Comandos POP3 Importantes

| Comando       | Función             |
| ------------- | ------------------- |
| USER username | Usuario             |
| PASS password | Contraseña          |
| STAT          | Cantidad de correos |
| LIST          | Lista correos       |
| RETR id       | Descarga correo     |
| DELE id       | Borra correo        |
| QUIT          | Cierra conexión     |

---

# 7. Configuraciones Peligrosas

Algunas configuraciones de Dovecot que pueden filtrar información:

| Setting                 | Riesgo                       |
| ----------------------- | ---------------------------- |
| auth_debug              | Log detallado autenticación  |
| auth_debug_passwords    | Log de contraseñas           |
| auth_verbose            | Muestra fallos autenticación |
| auth_anonymous_username | Login anónimo                |

Una mala configuración puede permitir:

* Enumeración de usuarios
* Extracción de credenciales
* Lectura completa del buzón

---

# 8. Footprinting con Nmap

Comando:

```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

Salida completa:

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 22:09 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00026s latency).

PORT    STATE SERVICE  VERSION
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE SASL STLS TOP UIDL RESP-CODES CAPA PIPELINING
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: more have post-login STARTTLS Pre-login capabilities LITERAL+ LOGIN-REFERRALS OK LOGINDISABLEDA0001 SASL-IR ENABLE listed IDLE ID IMAP4rev1
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
993/tcp open  ssl/imap Dovecot imapd
|_imap-capabilities: more have post-login OK capabilities LITERAL+ LOGIN-REFERRALS Pre-login AUTH=PLAINA0001 SASL-IR ENABLE listed IDLE ID IMAP4rev1
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
995/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE USER SASL(PLAIN) TOP UIDL RESP-CODES CAPA PIPELINING
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

Información relevante:

* Nombre común del certificado: mail1.inlanefreight.htb
* Organización: Inlanefreight
* Ubicación: California
* Servicio: Dovecot

---

# 9. Interacción con cURL (IMAPS)

```
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd
```

Salida:

```
* LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." INBOX
```

---

# 10. Interacción Verbose con TLS

```
curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
```

(Salida completa incluida exactamente como en el material original)

```
*   Trying 10.129.14.128:993...
* TCP_NODELAY set
* Connected to 10.129.14.128 (10.129.14.128) port 993 (#0)
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: /etc/ssl/certs
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Server certificate:
*  subject: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  start date: Sep 19 19:44:58 2021 GMT
*  expire date: Jul  4 19:44:58 2295 GMT
*  issuer: C=US; ST=California; L=Sacramento; O=Inlanefreight; OU=Customer Support; CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
< * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
> A001 CAPABILITY
< * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN
< A001 OK Pre-login capabilities listed, post-login capabilities have more.
> A002 AUTHENTICATE PLAIN AGNyeTBsMXQzADEyMzQ=
< A002 OK Logged in
> A003 LIST "" *
< * LIST (\HasNoChildren) "." Important
< * LIST (\HasNoChildren) "." INBOX
< A003 OK List completed (0.001 + 0.000 secs).
```

---

# 11. Interacción con OpenSSL

POP3S:

```
openssl s_client -connect 10.129.14.128:pop3s
```

IMAPS:

```
openssl s_client -connect 10.129.14.128:imaps
```

(Las salidas TLS completas son equivalentes a las mostradas anteriormente, incluyendo detalles de sesión TLSv1.3, cipher TLS_AES_256_GCM_SHA384 y certificado autofirmado.)

---

# 12. Caso Práctico – Credenciales Descubiertas

Si previamente descubrimos:

```
robin:robin
```

Podemos intentar autenticarnos vía:

* IMAP
* POP3

Y potencialmente:

* Leer emails internos
* Extraer credenciales
* Escalar acceso

---



# Preguntas


#### Descubra el nombre exacto de la organización del servicio IMAP/POP3 y envíelo como respuesta.

#### ¿Cuál es el FQDN al que están asignados los servidores IMAP y POP3?


#### Enumere el servicio IMAP y envíe la bandera como respuesta. (Formato: HTB{...})


#### ¿Cuál es la versión personalizada del servidor POP3?


#### ¿Cuál es la dirección de correo electrónico del administrador?

#### Intente acceder a los correos electrónicos en el servidor IMAP y envíe la bandera como respuesta. (Formato: HTB{...})
