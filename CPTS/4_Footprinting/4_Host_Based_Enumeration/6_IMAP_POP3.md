# IMAP / POP3 

---

## 1. Contexto General: ¿Qué Problema Resuelven?

Cuando enviamos un correo electrónico intervienen varios protocolos distintos.

* **SMTP** → Se encarga de ENVIAR el correo.
* **IMAP / POP3** → Se encargan de RECIBIR y acceder a los correos almacenados en el servidor.

Es importante entender algo fundamental:

👉 El correo electrónico no vive en tu computadora. Vive en un **servidor de correo remoto**.

Tu cliente de correo (Outlook, Thunderbird, Apple Mail, etc.) simplemente se conecta a ese servidor para:

* Ver mensajes
* Leer mensajes
* Organizarlos
* Eliminarlos

IMAP y POP3 son los protocolos que permiten hacer eso.

---

# 2. IMAP 

## 2.1 ¿Qué es IMAP realmente?

IMAP (Internet Message Access Protocol) es un protocolo de red que permite gestionar correos electrónicos directamente en el servidor remoto.

Es importante la frase: **"directamente en el servidor"**.

Esto significa que:

* Los correos permanecen almacenados en el servidor.
* El cliente trabaja sobre ese almacenamiento remoto.
* Los cambios se reflejan en todos los dispositivos.

---

## 2.2 IMAP como "Sistema de Archivos Remoto"

Una forma muy clara de entender IMAP es imaginarlo como un:

📁 Sistema de archivos remoto para emails.

Así como en una carpeta compartida de red puedes:

* Crear carpetas
* Mover archivos
* Renombrarlos
* Eliminarlos

Con IMAP puedes:

* Crear carpetas de correo
* Mover mensajes entre carpetas
* Marcar mensajes como leídos
* Aplicar flags (importante, respondido, etc.)

Y todo esto ocurre en el servidor.

---

## 2.3 Sincronización Multi-Dispositivo

Una de las características más importantes de IMAP es la sincronización.

Ejemplo:

* Lees un correo desde tu celular.
* Luego abres tu laptop.
* El correo aparece como leído.

¿Por qué?

Porque el estado del mensaje se guarda en el servidor.

IMAP permite que múltiples clientes trabajen sobre el mismo buzón sin generar inconsistencias.

---

## 2.4 Funcionamiento Técnico

IMAP es un protocolo:

* Basado en modelo cliente-servidor.
* Basado en texto (comandos ASCII).
* Interactivo.

Puerto por defecto:

* 143 → IMAP sin cifrado
* 993 → IMAP sobre SSL/TLS (IMAPS)

Sin cifrado, transmite en texto plano:

* Usuario
* Contraseña
* Comandos
* Contenido del correo

Por eso en entornos reales se utiliza IMAPS.

---

## 2.5 Flujo de Conexión Paso a Paso

Cuando un cliente se conecta:

1. Se establece conexión TCP al puerto 143 o 993.
2. El servidor envía un banner inicial.
3. El cliente consulta las capacidades (CAPABILITY).
4. El usuario se autentica (usuario + contraseña).
5. El cliente selecciona un buzón (por ejemplo INBOX).
6. Puede listar, leer o modificar mensajes.

IMAP utiliza identificadores en cada comando, por ejemplo:

```
A001 LOGIN usuario contraseña
A002 SELECT INBOX
```

El servidor responde usando ese mismo identificador.

Esto permite enviar múltiples comandos sin esperar respuesta inmediata.

---

## 2.6 Trabajo Online

IMAP necesita conexión activa al servidor.

Si no hay conexión:

* No se pueden gestionar correos.

Algunos clientes permiten modo offline:

* Se trabaja sobre copia local.
* Luego se sincronizan los cambios cuando vuelve la conexión.

---

## 2.7 Ventajas y Desventajas

Ventajas:

* Sincronización entre dispositivos.
* Organización avanzada con carpetas.
* Acceso simultáneo multiusuario.

Desventajas:

* Mayor consumo de almacenamiento en servidor.
* Mayor complejidad.

---

# 3. POP3 

## 3.1 ¿Qué es POP3?

POP3 (Post Office Protocol v3) es un protocolo más antiguo y más simple.

Su objetivo principal es:

📥 Descargar correos del servidor.

Y tradicionalmente:

🗑 Eliminarlos del servidor después de descargarlos.

---

## 3.2 Modelo de Funcionamiento

POP3 funciona de forma mucho más básica:

1. Cliente se conecta al servidor.
2. Se autentica.
3. Descarga todos los correos.
4. Opcionalmente los elimina del servidor.
5. Cierra conexión.

No mantiene sincronización compleja.

---

## 3.3 Capacidades Limitadas

POP3 permite únicamente:

* LIST → Listar correos.
* RETR → Descargar correo.
* DELE → Eliminar correo.

No permite:

* Carpetas jerárquicas.
* Acceso a múltiples buzones.
* Flags avanzados.
* Gestión estructurada.

---

## 3.4 Puertos

* 110 → POP3 sin cifrar
* 995 → POP3 sobre SSL/TLS (POP3S)

---

# 4. Comparación Conceptual Profunda

## IMAP = Trabajo remoto sincronizado

El correo vive en el servidor.
El cliente es una interfaz.

## POP3 = Descarga local

El correo se mueve del servidor al cliente.
El cliente se convierte en el almacenamiento principal.

---

# 5. Relación con SMTP

SMTP se utiliza para enviar correos.

Cuando envías un email:

* El cliente usa SMTP.
* El servidor lo entrega.
* Luego puede guardarse en una carpeta IMAP llamada "Sent".

Gracias a IMAP:

* Todos los dispositivos pueden ver los correos enviados.

---

# 6. Seguridad y Cifrado

IMAP y POP3 sin cifrado transmiten todo en texto plano.

Esto incluye:

* Credenciales
* Contenido del mensaje

Por eso se utiliza SSL/TLS.

Dependiendo de la implementación:

* IMAP puede usar STARTTLS en puerto 143.
* O directamente 993 (IMAPS).

Lo mismo aplica para POP3 con 995.

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
