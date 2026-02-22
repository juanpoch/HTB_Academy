# FTP y TFTP (Footprinting / Enumeración)

> Sección del curso **Footprinting** (HTB Academy) enfocada en **FTP**/**TFTP**: conceptos, modos de operación, configuración típica con **vsFTPd**, settings peligrosos y técnicas prácticas de enumeración.

---

## 1) FTP (File Transfer Protocol)

### ¿Qué es FTP?

[**FTP**](https://datatracker.ietf.org/doc/html/rfc959) es uno de los protocolos más antiguos de Internet para **transferencia de archivos**. Opera en la **capa de aplicación** del stack TCP/IP, al igual que **HTTP** o **POP**. Puede utilizarse mediante:

* Clientes dedicados (CLI/GUI).
* Herramientas integradas en sistemas operativos.
* Aplicaciones que lo consumen como “backend” para subir/bajar archivos.

### Canales en FTP: control vs datos

Una conexión FTP **abre dos canales**:

1. **Canal de control (TCP/21)**

* Se usa para **comandos** del cliente y **códigos de estado** del servidor.
* Es donde viajan acciones como `USER`, `PASS`, `LIST`, `RETR`, `STOR`, etc.

2. **Canal de datos (típicamente TCP/20 en modo activo)**

* Se usa **exclusivamente** para la **transferencia** (listados, descargas, subidas).
* El protocolo controla errores durante la transmisión.
* Si una transferencia se corta, suele poder **reanudarse** tras reestablecer contacto (según cliente/servidor/escenario).

> Idea clave para footprinting: **ver banner/códigos por 21** y confirmar **cómo se abre el canal de datos** (activo/pasivo) suele explicar fallos “raros” detrás de firewalls.

---

## 2) FTP Activo vs FTP Pasivo

### FTP Activo

* Cliente conecta al **control** (TCP/21).
* Cliente le indica al servidor **qué puerto del cliente** usar para el canal de datos.
* Problema típico: si el **cliente está detrás de firewall**, el servidor no puede “volver” por conexiones entrantes → la transferencia se rompe.

### FTP Pasivo (PASV)

* Se creó para evitar el problema anterior.
* El **servidor anuncia un puerto** y el **cliente inicia** la conexión del canal de datos.
* Como el cliente inicia el flujo, el firewall suele permitirlo.

> En práctica de pentest, si ves mensajes como “Consider using PASV”, probá cambiar a modo pasivo. En entornos reales, FTP detrás de NAT/firewall suele depender de PASV.

---

## 3) Comandos y códigos de estado

FTP define [**muchos comandos**](https://web.archive.org/web/20230326204635/https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/) y [**códigos de estado**](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes), pero **no todos** están implementados igual en todos los servidores.

* El cliente puede pedir: subir/bajar archivos, listar/crear/borrar directorios, renombrar, etc.
* El servidor responde con **status codes** (ej.: `220`, `230`, `150`, `226`, etc.) indicando si se ejecutó y el resultado.

**Ejemplos vistos en interacción:**

* `220` → banner / servicio listo.
* `230` → login exitoso.
* `150` → abriendo conexión de datos (listado/transferencia).
* `226` → transferencia/listado completado.

---

## 4) Credenciales, texto plano y Anonymous FTP

### Credenciales

Normalmente se requieren credenciales válidas para usar FTP.

### FTP es clear-text

FTP (clásico) es un protocolo **en texto plano**: usuario/contraseña y comandos pueden ser **sniffeables** si se dan condiciones de red que lo permitan.

### Anonymous FTP

Algunos servidores permiten **acceso anónimo**:

* Permite subir/bajar archivos **sin contraseña real**.
* Por riesgo, suele estar **limitado** (permisos/restricciones/chroot).

> Para footprinting, incluso si no podés descargar, el simple **listado (ls)** puede filtrar información útil (nombres de proyectos, clientes, plantillas, estructura interna, usuarios/roles, etc.).

---

## 5) TFTP (Trivial File Transfer Protocol)

### ¿Qué es TFTP?

**TFTP** es una versión más simple que FTP para transferencias.

* **No ofrece autenticación** de usuarios.
* Carece de funciones “avanzadas” típicas de FTP.
* Usa **UDP** (no TCP) → es **no confiable** y se apoya en recuperación a nivel aplicación.

### Implicancia práctica de seguridad

* No hay login con password.
* El acceso se controla básicamente con permisos de archivos/OS.
* En la práctica, opera en directorios/archivos que estén **globalmente compartidos** (lectura/escritura amplia).
* Por falta de seguridad, suele restringirse a **redes locales y protegidas**.

### Comandos típicos de TFTP

| Comando   | Descripción                                                     |
| --------- | --------------------------------------------------------------- |
| `connect` | Define host remoto (y opcionalmente puerto) para transferencias |
| `get`     | Descarga archivo(s) desde el remoto al local                    |
| `put`     | Sube archivo(s) del local al remoto                             |
| `quit`    | Sale del cliente                                                |
| `status`  | Muestra estado: modo (ascii/binary), conexión, timeouts, etc.   |
| `verbose` | Activa/desactiva salida detallada                               |

**Limitación importante:** a diferencia de FTP, TFTP **no** tiene funcionalidad de **listado de directorios**.

---

## 6) Configuración por defecto: vsFTPd

Uno de los servidores FTP más usados en Linux es [**vsFTPd**](https://security.appspot.com/vsftpd.html).

* Archivo principal: `/etc/vsftpd.conf`
* Se recomienda montarlo en una VM y revisar opciones reales.

### Instalación (Debian/Ubuntu)

```bash
sudo apt install vsftpd
```

> vsFTPd es “uno de varios” servidores FTP. Se usa mucho para demostrar configuraciones de forma simple. No todas las opciones están en el archivo por defecto: el resto está en el [**man page**](http://vsftpd.beasts.org/vsftpd_conf.html).

### Opciones típicas (ejemplo de `vsftpd.conf`)

> Ejemplo mostrado filtrando comentarios: `cat /etc/vsftpd.conf | grep -v "#"`

<img width="606" height="256" alt="image" src="https://github.com/user-attachments/assets/3fa1b54f-39f9-43f1-8740-3e2faa176455" />


| Setting                                   | Descripción                                  |
| ----------------------------------------- | -------------------------------------------- |
| `listen=NO`                               | ¿Corre desde inetd o como daemon standalone? |
| `listen_ipv6=YES`                         | ¿Escucha en IPv6?                            |
| `anonymous_enable=NO`                     | ¿Habilita acceso anónimo?                    |
| `local_enable=YES`                        | ¿Permite login de usuarios locales?          |
| `dirmessage_enable=YES`                   | ¿Muestra mensajes al entrar a directorios?   |
| `use_localtime=YES`                       | ¿Usa hora local?                             |
| `xferlog_enable=YES`                      | ¿Loguea subidas/descargas?                   |
| `connect_from_port_20=YES`                | ¿Conexión de datos desde puerto 20 (activo)? |
| `secure_chroot_dir=/var/run/vsftpd/empty` | Directorio vacío para chroot seguro          |
| `pam_service_name=vsftpd`                 | Servicio PAM usado por vsftpd                |
| `rsa_cert_file=...`                       | Ubicación del cert RSA (SSL/TLS)             |
| `rsa_private_key_file=...`                | Ubicación de la private key                  |
| `ssl_enable=NO`                           | ¿Habilita SSL/TLS?                           |

### Archivo a vigilar: `/etc/ftpusers`

Este archivo se usa para **negar acceso** a usuarios específicos.
Ejemplo:

<img width="696" height="286" alt="image" src="https://github.com/user-attachments/assets/e6c32437-f7df-4952-9411-bb28ce0d7e85" />


Aunque existan como usuarios del sistema, **no podrán** loguearse por FTP si están listados ahí.

---

## 7) Settings peligrosos / misconfig típicas

### Anonymous login habilitado + escritura

En vsFTPd, habilitar anónimo y permitir escritura puede ser crítico.
[Opciones](http://vsftpd.beasts.org/vsftpd_conf.html) típicas (cuando existen):

| Setting                        | Descripción                                                                                     |
| ------------------------------ | ----------------------------------------------------------------------------------------------- |
| `anonymous_enable=YES`         | Permite login anónimo                                                                           |
| `anon_upload_enable=YES`       | Permite subir archivos como anónimo                                                             |
| `anon_mkdir_write_enable=YES`  | Permite crear directorios como anónimo                                                          |
| `no_anon_password=YES`         | No pide password a anónimo                                                                      |
| `anon_root=/home/username/ftp` | Directorio root para anónimo                                                                    |
| `write_enable=YES`             | Habilita comandos de escritura: `STOR`, `DELE`, `RNFR/RNTO`, `MKD`, `RMD`, `APPE`, `SITE`, etc. |

**Riesgo típico:**

* Acceso a información sensible.
* Subida de archivos “maliciosos” o de pivote (ej.: webshell si hay sincronización con webroot).
* Abuso de logs/paths para ejecución remota en escenarios concretos.

> Ojo: a veces en infra interna se habilita para “compartir rápido”, pero si esa interfaz termina expuesta o puenteada, se vuelve un punto de entrada.

---

## 8) Interacción práctica con `ftp` (Anonymous)

### Login anónimo

```bash
ftp <IP>
```

Ejemplo de flujo:

* El servidor responde con `220` y un **banner**.
* Ingresás `anonymous` como usuario.
* Si permite, responde `230 Login successful`.

### Enumeración inicial (listado)

Dentro del prompt `ftp>`:

```ftp
ls
```

El listado puede mostrar:

* Archivos sueltos (`.pptx`, `.txt`, etc.).
* Directorios por área (Clients, Documents, Employees…).
* Permisos (útil para inferir si hay escritura habilitada).

### Ver estado (overview del cliente/sesión)

```ftp
status
```

Sirve para ver:

* Modo actual (binario/ascii).
* Si usa comandos PORT.
* Flags de cliente.

### Más detalle: `debug` y `trace`

```ftp
debug
trace
```

Luego, por ejemplo:

```ftp
ls
```

Vas a ver los comandos reales enviados (ej.: `PORT`, `LIST`) y respuestas del servidor.

---

## 9) Settings útiles que impactan enumeración

### `hide_ids=YES`

Si está activo, el listado muestra user/group como `ftp` en lugar de UID/GID reales.

* **Pro:** evita filtrar usuarios locales.
* **Contra para el atacante:** perdés señales sobre qué usuarios/grupos reales están asociados a archivos.

### `ls_recurse_enable=YES`

Permite listados recursivos:

```ftp
ls -R
```

Útil para ver rápidamente:

* Estructura completa.
* Subdirectorios relevantes.
* Nombres de archivos con valor (contratos, plantillas, notas internas, etc.).

---

## 10) Transferencias: descargar y subir

### Descargar un archivo (RETR)

Ejemplo con espacios escapados:

```ftp
get Important\ Notes.txt
```

Resultado típico:

* `150 Opening BINARY mode data connection ...`
* `226 Transfer complete.`

### Descargar “todo” con `wget` (mirror)

Para obtener todo lo accesible (útil en jerarquías grandes, pero ruidoso):

```bash
wget -m --no-passive ftp://anonymous:anonymous@<IP>
```

Notas:

* `-m` crea un “mirror” y guarda estructura.
* Suele crear un directorio con nombre del host/IP destino.
* **Riesgo operacional:** puede disparar alertas por volumen/behavior.

### Subir un archivo (STOR)

Crear archivo local:

```bash
touch testupload.txt
```

Luego en `ftp>`:

```ftp
put testupload.txt
```

Si se permite escritura, verás `150 Ok to send data` y `226 Transfer complete`.

**Por qué importa en pentest:**

* Si FTP está vinculado a un servidor web o a un proceso de sincronización, una subida puede convertirse en **ejecución** (ej.: acceso directo a webshell) y derivar en **reverse shell** / ejecución de comandos.

---

## 11) Footprinting con Nmap + NSE

### Actualizar base de scripts NSE

```bash
sudo nmap --script-updatedb
```

### Encontrar scripts FTP en el sistema

```bash
find / -type f -name ftp* 2>/dev/null | grep scripts
```

Ejemplos típicos:

* `ftp-anon.nse` (chequea anónimo + lista contenido)
* `ftp-syst.nse` (usa `STAT`/`SYST` para info del server)
* `ftp-brute.nse` (fuerza bruta — usar sólo si está permitido)
* Scripts específicos de vulnerabilidades/backdoors (dependen de versiones/targets).

### Escaneo recomendado (servicio estándar 21)

```bash
sudo nmap -sV -p21 -sC -A <IP>
```

Qué aporta:

* `-sV`: versión del servicio.
* `-sC`: scripts por defecto (incluye checks útiles como `ftp-anon`, `ftp-syst` si aplica).
* `-A`: agresivo (detecciones extra).

**Interpretación típica de salida:**

* Confirma `21/tcp open ftp`.
* Indica servidor (ej.: `vsftpd`).
* `ftp-anon` puede listar contenido y marcar si hay **writeable**.
* `ftp-syst` puede devolver status del server (incluye si control/datos son texto plano).

### Traza de scripts (qué comandos viajan)

```bash
sudo nmap -sV -p21 -sC -A <IP> --script-trace
```

Permite ver:

* Conexiones paralelas.
* Puertos origen efímeros.
* Banner recibido.
* Comandos enviados por NSE.

---

## 12) Interacción manual (netcat / telnet / TLS)

### Conectar a FTP por texto plano

```bash
nc -nv <IP> 21
```

```bash
telnet <IP> 21
```

Esto sirve para:

* Ver banner.
* Probar comandos manuales.
* Diagnosticar comportamientos de red.

### FTP con TLS/SSL (STARTTLS)

Cuando hay cifrado, necesitás un cliente que lo soporte. Ejemplo con OpenSSL:

```bash
openssl s_client -connect <IP>:21 -starttls ftp
```

**Valor del certificado en footprinting:**

* Puede revelar **hostname (CN/SAN)**.
* Puede incluir **email** de contacto.
* Puede indicar **organización/unidad** y **ubicación** (si el cert está bien rellenado).
* Si es self-signed, igual puede dar pistas internas.

---

## 13) Checklist rápido para tu writeup (práctico)

1. **Descubrir servicio**

   * `nmap -sV -p21 -sC -A <IP>`

2. **Revisar banner + soporte anónimo**

   * `ftp <IP>` → mirar `220` y probar `anonymous`

3. **Enumerar estructura**

   * `ls` / `ls -R` (si habilitado)
   * Tomar nota de nombres de archivos/directorios

4. **Validar permisos**

   * Intentar `get <archivo>`
   * Intentar `put <archivo>` (si está permitido y dentro de reglas del engagement)

5. **Profundizar**

   * `status`, `debug`, `trace`
   * `--script-trace` en Nmap si querés ver tráfico

6. **Si hay TLS**

   * `openssl s_client -starttls ftp` y extraer pistas del cert

---

## 14) Notas de seguridad (en modo reporte)

* FTP clásico es **texto plano** (riesgo de sniffing).
* Anonymous FTP puede exponer información y/o permitir escritura.
* La posibilidad de **upload** en un FTP asociado a un webserver o a un pipeline de despliegue incrementa severidad (potencial RCE).
* Incluso sin descarga, el simple **listing** puede filtrar inteligencia (nombres de clientes, documentos, estructura interna).

---

> Fin del writeup. Si querés, después lo extendemos con una sección “**Findings típicos**” (severidad, impacto, evidencias y recomendaciones) para que quede 100% listo para reporte/pentest real.
