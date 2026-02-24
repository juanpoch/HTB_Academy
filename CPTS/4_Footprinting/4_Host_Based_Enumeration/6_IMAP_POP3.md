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

## 📧 Cómo Viaja un Correo Electrónico en Internet

---

### 1️⃣ Introducción

Cuando enviamos un correo electrónico, no viaja directamente desde nuestra computadora a la del destinatario.

En realidad, intervienen múltiples servidores y varios protocolos diferentes.

Para entenderlo correctamente, debemos separar el proceso en tres partes:

1. Envío del correo
2. Transferencia entre servidores
3. Acceso al correo por el destinatario

---

## 2️⃣ Escenario de Ejemplo

Supongamos:

* Remitente: `juan@empresaA.com`
* Destinatario: `ana@empresaB.com`

Ahora veremos paso a paso qué ocurre.

---

## 3️⃣ Paso 1 – El Cliente Envía el Correo (SMTP)

Juan escribe un correo en su cliente:

* Outlook
* Thunderbird
* Gmail App
* Webmail

Ese programa es el **cliente de correo**.

Cuando Juan presiona "Enviar":

🔹 El cliente usa el protocolo **SMTP (Simple Mail Transfer Protocol)**.

El flujo es:

Cliente de Juan
→ (SMTP) →
Servidor SMTP de empresaA

SMTP se utiliza exclusivamente para enviar correos.

Puertos comunes:

* 25 (servidor a servidor)
* 587 (cliente autenticado)
* 465 (SMTP sobre SSL/TLS)

---

## 4️⃣ Paso 2 – Búsqueda del Servidor del Destinatario (DNS + MX)

Ahora el servidor de empresaA necesita saber:

👉 ¿Dónde entrego correos para `empresaB.com`?

Para eso consulta el DNS.

Específicamente busca los registros:

📌 **MX (Mail Exchange Records)**

Ejemplo:

```
empresaB.com   MX   mail.empresaB.com
```

Esto indica cuál es el servidor que recibe correos para ese dominio.

---

## 5️⃣ Paso 3 – Transferencia Entre Servidores (SMTP nuevamente)

Una vez obtenido el registro MX:

Servidor SMTP de empresaA
→ (SMTP) →
Servidor SMTP de empresaB

Aquí se vuelve a usar SMTP.

Importante:

SMTP no solo lo usa el cliente.
También lo usan los servidores entre sí.

---

## 6️⃣ Paso 4 – Almacenamiento en el Servidor del Destinatario

El servidor de empresaB:

* Recibe el mensaje.
* Lo almacena en el buzón de Ana.

En este momento el correo ya llegó.

Pero Ana todavía no lo ha leído.

---

## 7️⃣ Paso 5 – El Destinatario Accede al Correo (IMAP o POP3)

Cuando Ana abre su cliente de correo:

Su cliente se conecta al servidor usando:

🔹 IMAP
o
🔹 POP3

Aquí es donde estos protocolos entran en juego.

---

### 📌 Si usa IMAP

Cliente de Ana
→ (IMAP) →
Servidor de empresaB

Características:

* El correo permanece en el servidor.
* Se sincroniza entre dispositivos.
* Permite carpetas jerárquicas.
* Permite múltiples clientes simultáneamente.

Puertos:

* 143 (sin cifrar)
* 993 (IMAPS – cifrado TLS)

---

### 📌 Si usa POP3

Cliente de Ana
→ (POP3) →
Servidor de empresaB

Características:

* Descarga los correos.
* Puede eliminarlos del servidor.
* No sincroniza estados avanzados.

Puertos:

* 110 (sin cifrar)
* 995 (POP3S – cifrado TLS)

---

## 8️⃣ Diagrama Completo del Flujo

```
Juan (Cliente)
   ↓ SMTP
Servidor SMTP empresaA
   ↓ DNS (consulta MX)
   ↓ SMTP
Servidor SMTP empresaB
   ↓ Almacenamiento
Buzón de Ana
   ↓ IMAP o POP3
Cliente de Ana
```

---

## 9️⃣ Resumen de Protocolos Utilizados

| Etapa                          | Protocolo | Función                        |
| ------------------------------ | --------- | ------------------------------ |
| Envío desde cliente            | SMTP      | Enviar correo                  |
| Transferencia entre servidores | SMTP      | Entregar correo                |
| Acceso del destinatario        | IMAP      | Leer y sincronizar en servidor |
| Acceso del destinatario        | POP3      | Descargar correo               |
| Resolución de destino          | DNS (MX)  | Indicar servidor receptor      |




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

# 7. Configuraciones Peligrosas en IMAP / POP3 

---

Antes de hablar de configuraciones peligrosas, necesitamos entender algo fundamental:

IMAP y POP3 no existen “solos”.

Son protocolos que son implementados por un software de servidor de correo.

Uno de los más utilizados en entornos Linux es:

👉 **Dovecot**

Dovecot es un software que permite:

* Proveer servicio IMAP
* Proveer servicio POP3
* Gestionar autenticación
* Acceder al almacenamiento de buzones

Por lo tanto, cuando hablamos de "configuraciones peligrosas", en realidad hablamos de configuraciones del software que implementa estos protocolos.

---

# 7.1 ¿Qué es una configuración del servidor de correo?

Se puede experimentar instalando `dovecot-imapd` y `dovecot-pop3d`.

- [Dovecot: configuraciones individuales](https://doc.dovecot.org/2.4.1/core/summaries/settings.html)
- [Dovecot: Opciones de configuración del servicio](https://doc.dovecot.org/2.4.1/core/config/service.html)

## 📘 Comandos IMAP y POP3 

---

### 📌 1️⃣ Comandos IMAP

IMAP es un protocolo más complejo y permite gestionar el buzón directamente en el servidor.

| Comando                         | Explicación Técnica                                                                                  | Qué Significa en la Práctica                            |
| ------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `1 LOGIN username password`     | Autentica al usuario en el servidor IMAP. El número inicial (ej: 1) es un identificador del comando. | Inicia sesión con usuario y contraseña.                 |
| `1 LIST "" *`                   | Lista todas las carpetas o buzones disponibles en la cuenta.                                         | Muestra INBOX y cualquier carpeta creada.               |
| `1 CREATE "INBOX"`              | Crea un nuevo buzón o carpeta en el servidor.                                                        | Permite crear una carpeta nueva para organizar correos. |
| `1 DELETE "INBOX"`              | Elimina un buzón del servidor.                                                                       | Borra una carpeta completa.                             |
| `1 RENAME "ToRead" "Important"` | Cambia el nombre de un buzón existente.                                                              | Renombra una carpeta de correo.                         |
| `1 LSUB "" *`                   | Lista únicamente los buzones suscritos por el usuario.                                               | Muestra carpetas activas o marcadas como visibles.      |
| `1 SELECT INBOX`                | Selecciona una carpeta para trabajar sobre ella.                                                     | Abre la bandeja de entrada para leer correos.           |
| `1 UNSELECT INBOX`              | Cierra el buzón seleccionado sin cerrar sesión.                                                      | Sale de la carpeta actual.                              |
| `1 FETCH <ID> all`              | Recupera toda la información de un mensaje específico.                                               | Descarga o muestra un correo concreto.                  |
| `1 CLOSE`                       | Elimina mensajes marcados con la bandera "Deleted".                                                  | Borra definitivamente correos previamente marcados.     |
| `1 LOGOUT`                      | Finaliza la sesión IMAP.                                                                             | Cierra la conexión con el servidor.                     |

🔎 Nota importante:

En IMAP cada comando lleva un identificador (por ejemplo `1`, `A001`, etc.). Esto permite que el servidor asocie respuestas a cada solicitud enviada.

---

### 📌 2️⃣ Comandos POP3

POP3 es más simple y está diseñado principalmente para descargar correos.

| Comando         | Explicación Técnica                                               | Qué Significa en la Práctica                        |
| --------------- | ----------------------------------------------------------------- | --------------------------------------------------- |
| `USER username` | Envía el nombre de usuario al servidor.                           | Indica qué cuenta quiere autenticarse.              |
| `PASS password` | Envía la contraseña asociada al usuario.                          | Completa el proceso de login.                       |
| `STAT`          | Devuelve el número total de mensajes y el tamaño total del buzón. | Muestra cuántos correos hay.                        |
| `LIST`          | Lista todos los mensajes junto con su tamaño en bytes.            | Permite ver qué correos están disponibles.          |
| `RETR id`       | Recupera el mensaje especificado por su número.                   | Descarga un correo concreto.                        |
| `DELE id`       | Marca un mensaje para eliminación.                                | Borra un correo del servidor.                       |
| `CAPA`          | Muestra las capacidades soportadas por el servidor.               | Indica qué funciones adicionales están disponibles. |
| `RSET`          | Restablece el estado de la sesión actual.                         | Cancela eliminaciones pendientes.                   |
| `QUIT`          | Finaliza la sesión POP3.                                          | Cierra la conexión con el servidor.                 |

---

# 📌 Diferencia Conceptual Importante

IMAP permite gestionar y organizar el buzón en el servidor.

POP3 permite principalmente descargar y eliminar correos.

IMAP = Administración remota del buzón.

POP3 = Descarga simple de correos.

---


Cuando un administrador instala Dovecot, puede configurar:

* Cómo se autentican los usuarios
* Qué se registra en logs
* Qué mecanismos de autenticación están habilitados
* Si se permite acceso anónimo
* Qué nivel de detalle se guarda en auditorías

Estas configuraciones suelen estar en archivos como:

```
/etc/dovecot/dovecot.conf
```

O dentro del directorio:

```
/etc/dovecot/conf.d/
```

Una mala configuración puede generar exposición de información sensible.

---

# 7.2 ¿Por qué las configuraciones pueden ser peligrosas?

Porque los servidores de correo manejan:

* Credenciales de usuarios
* Comunicaciones privadas
* Información corporativa sensible
* Datos financieros o estratégicos

Si el servidor está mal configurado, un atacante podría:

* Enumerar usuarios válidos
* Obtener credenciales
* Leer correos internos
* Obtener información para escalar privilegios

---

# 7.3 Configuraciones Peligrosas en Dovecot

A continuación analizamos cada configuración mencionada en el material original, pero explicada de forma clara.

---

## 7.3.1 auth_debug

**Qué hace:**

Activa logs detallados sobre el proceso de autenticación.

Eso significa que el servidor registra información muy específica sobre cómo se están validando los usuarios.

**Por qué es peligroso:**

Si esos logs son accesibles (por ejemplo mediante una vulnerabilidad de lectura de archivos), podrían revelar:

* Intentos de autenticación
* Usuarios existentes
* Flujo interno de validación

Esto facilita enumeración de usuarios.

---

## 7.3.2 auth_debug_passwords

**Qué hace:**

Aumenta el nivel de detalle del log y puede registrar las contraseñas enviadas durante la autenticación.

**Esto es extremadamente peligroso.**

Porque si el log guarda:

* Usuario
* Contraseña enviada

Un atacante que acceda a los logs podría obtener credenciales reales.

---

## 7.3.3 auth_verbose

**Qué hace:**

Registra intentos fallidos de autenticación y el motivo del fallo.

Ejemplo peligroso:

Si el servidor responde distinto cuando:

* El usuario no existe
* La contraseña es incorrecta

Esto permite:

👉 Enumeración de usuarios válidos.

Un atacante podría probar múltiples usernames y ver cuáles generan una respuesta diferente.

---

## 7.3.4 auth_verbose_passwords

Similar a auth_debug_passwords.

Puede registrar contraseñas usadas durante intentos de autenticación.

Incluso si están truncadas, sigue siendo información sensible.

---

## 7.3.5 auth_anonymous_username

Esta configuración define qué usuario se utiliza cuando alguien se autentica usando el mecanismo SASL ANONYMOUS.

En términos simples:

Podría permitir login anónimo.

Si el servidor permite autenticación anónima sin restricciones, podría permitir acceso a buzones sin credenciales válidas.

Esto sería equivalente a un "anonymous FTP" pero en correo.

---

# 7.4 Relación con IMAP y POP3

Recordemos algo importante:

IMAP y POP3 son protocolos basados en texto.

Un atacante puede interactuar directamente usando:

* telnet
* netcat
* openssl

Si el servidor está mal configurado, podría revelar información mediante:

* Mensajes de error detallados
* Capabilities mal configuradas
* Autenticación débil

---

# 7.5 Escenario de Riesgo Real

Supongamos:

1. El servidor tiene auth_verbose habilitado.
2. Un atacante prueba usuarios.
3. El servidor responde diferente si el usuario existe.

Resultado:

El atacante obtiene una lista de usuarios válidos.

Luego:

4. Realiza ataques de fuerza bruta.
5. Obtiene acceso.
6. Puede leer correos internos.

Impacto potencial:

* Filtración de información confidencial.
* Obtención de credenciales reutilizadas.
* Movimiento lateral dentro de la red.

---

# 7.6 Por Qué Muchas Empresas Usan Proveedores Externos

Empresas como:

* Google
* Microsoft

Invierten enormes recursos en:

* Hardening
* Auditorías
* Seguridad de configuración

Mantener un servidor propio requiere:

* Configuración correcta
* Monitoreo constante
* Gestión de logs segura

Errores de configuración pueden convertir el servidor en un punto crítico de compromiso.





---


# 8. Footprinting con Nmap


## Puertos por Defecto de IMAP y POP3

Por defecto, los protocolos de correo utilizan los siguientes puertos:

- **POP3**
  - 110 → Sin cifrado
  - 995 → POP3 sobre SSL/TLS (cifrado)

- **IMAP**
  - 143 → Sin cifrado
  - 993 → IMAP sobre SSL/TLS (cifrado)

Los puertos más altos (**993 y 995**) utilizan **TLS/SSL**, lo que significa que la comunicación entre el cliente y el servidor viaja cifrada. Esto protege:

- Credenciales (usuario y contraseña)
- Contenido de los correos
- Comandos enviados al servidor

Si el servidor utiliza TLS/SSL, herramientas como **Nmap** pueden detectar esta configuración y mostrar información adicional, como:

- Detalles del certificado digital
- Nombre común (CN)
- Organización
- Fechas de validez del certificado

Esta información puede ser útil durante tareas de reconocimiento o análisis de seguridad.

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
