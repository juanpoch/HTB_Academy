# Linux Remote Management Protocols

## Introducción

En entornos Linux existen múltiples mecanismos para administrar servidores de forma remota. Esto permite a administradores y equipos de soporte acceder a sistemas ubicados en otras ciudades o incluso países sin necesidad de presencia física.

Desde la perspectiva de ciberseguridad y pentesting, estos servicios representan un objetivo crítico:

* Están expuestos con frecuencia en redes públicas e internas.
* Permiten acceso directo al sistema.
* Una mala configuración puede derivar en compromiso total del host.

En este documento analizaremos los principales protocolos de administración remota en Linux:

* SSH (Secure Shell)
* Rsync
* R-Services (rlogin, rsh, rexec, etc.)

---

# SSH (Secure Shell)

## ¿Qué es SSH?

SSH ([Secure Shell](https://en.wikipedia.org/wiki/Secure_Shell)) es el protocolo estándar para administración remota segura en sistemas Linux.

* Puerto por defecto: **TCP 22**
* Protocolo cifrado
* Permite ejecución remota de comandos
* Transferencia de archivos (SCP/SFTP)
* Port forwarding y túneles

SSH reemplazó a protocolos inseguros como Telnet y R-Services.

[OpenSSH](https://www.openssh.org/)

---

## Versiones del protocolo

Existen dos versiones principales:

* **SSH-1** → Vulnerable a ataques Man-in-the-Middle (MITM)
* **SSH-2** → Versión actual y segura

Ejemplo de banner:

```
SSH-2.0-OpenSSH_8.2p1
```

Esto indica:

* Protocolo soportado: SSH-2
* Servidor: OpenSSH 8.2p1

---

## Métodos de autenticación en OpenSSH

OpenSSH soporta múltiples métodos:

1. Password authentication
2. Public-key authentication
3. Host-based authentication
4. Keyboard-interactive
5. Challenge-response
6. GSSAPI authentication

Los más comunes en entornos reales son:

* Password
* Public Key


- Más [info](https://www.golinuxcloud.com/openssh-authentication-methods-sshd-config/) sobre métodos de autenticación.


---

# SSH – Autenticación por Clave Pública (Public Key Authentication)


---

## 1) Idea básica (en una frase)

En vez de probar tu identidad con **“algo que sabés”** (una contraseña), SSH te permite probarla con **“algo que tenés”**: una **clave privada** que *solo vos* deberías poseer.

* **Clave privada**: se queda en tu equipo. **Nunca** debe salir de ahí.
* **Clave pública**: se copia al servidor (por ejemplo en `~/.ssh/authorized_keys`).

El servidor te deja entrar si demostrás que realmente poseés la **clave privada** que corresponde a esa clave pública.

---

## 2) Antes de autenticarnos: ¿por qué hay 2 verificaciones?

En SSH pasan **dos cosas distintas**:

1. **El cliente verifica al servidor** (para evitar caer en un impostor).
2. **El servidor verifica al cliente** (para darte acceso).

---

# 3) Verificación del servidor (Server Authentication)

## 3.1 ¿Qué es la “host key” del servidor?

Cuando instalás OpenSSH server, el servidor genera unas claves propias llamadas **host keys** (por ejemplo):

* `/etc/ssh/ssh_host_ed25519_key` (privada)
* `/etc/ssh/ssh_host_ed25519_key.pub` (pública)

Estas claves identifican *a ese servidor*.

## 3.2 ¿Qué ocurre cuando te conectás por primera vez?

Cuando hacés:

```bash
ssh usuario@servidor
```

El servidor le envía al cliente su **host public key**.

Como es tu **primera conexión**, tu equipo todavía no sabe si ese servidor es realmente quien dice ser.

Por eso aparece el clásico mensaje:

* “The authenticity of host 'X' can't be established … Are you sure you want to continue connecting?”

Si aceptás, tu máquina guarda esa host key en:

* `~/.ssh/known_hosts`

A partir de ahí:

* Si alguien intenta hacerse pasar por el servidor y te presenta **otra host key**, SSH te avisa con un warning fuerte (posible MITM).

## 3.3 ¿Dónde está el riesgo real de MITM?

La ventana más peligrosa es **la primera vez** (cuando todavía no tenés una referencia confiable).

Por eso en entornos serios se valida la huella (fingerprint) por un canal confiable:

* consola/ILO/DRAC
* documentación interna
* contacto con admin

**Clave idea:** una host key no se puede “imitar” sin poseer la **clave privada** del servidor.

---

# 4) Verificación del cliente (Client Authentication)

Ahora viene lo que de verdad nos interesa: demostrarle al servidor que **sos vos**.

SSH permite varios métodos. Dos comunes:

* **Password authentication** (usuario + contraseña)
* **Public key authentication** (usuario + par de claves)

---

## 4.1 ¿Qué problema tiene la contraseña?

Aunque SSH cifra el canal, la contraseña:

* puede ser débil
* puede filtrarse/reutilizarse
* habilita fuerza bruta / password spraying

Además, es incómodo: te pide contraseña cada vez.

---

# 5) Public Key Authentication: cómo funciona paso a paso

Vamos con el flujo completo.

## 5.1 Generación del par de claves (en tu equipo)

Vos generás un par:

* **Clave privada** (secreta)
* **Clave pública** (se comparte)

Ejemplo típico:

```bash
ssh-keygen -t ed25519 -C "tu_email"
```

Eso crea archivos como:

* `~/.ssh/id_ed25519`  → **privada**
* `~/.ssh/id_ed25519.pub` → **pública**

### ¿Qué es la passphrase?

Al crear la clave privada, podés protegerla con una **passphrase** (una “contraseña” para desbloquear la clave privada).

* La passphrase **no viaja al servidor**.
* Solo sirve para que, si te roban el archivo de clave privada, no puedan usarlo fácilmente.

**Analogía rápida:**

* clave privada = “llave de la casa”
* passphrase = “caja fuerte donde guardás la llave”

---

## 5.2 Registrar tu clave pública en el servidor

El servidor necesita saber qué claves públicas están autorizadas para un usuario.

Se guardan en:

* `~/.ssh/authorized_keys`

Ejemplo (conceptual):

```bash
cat id_ed25519.pub >> ~/.ssh/authorized_keys
```

En la práctica, una forma típica es:

```bash
ssh-copy-id usuario@servidor
```

---

## 5.3 El momento clave: el “desafío criptográfico”

Cuando intentás conectar, el servidor hace esto:

1. Encuentra en `authorized_keys` una clave pública que podría corresponder al usuario.
2. Te manda un **desafío** (challenge) para que pruebes que tenés la **clave privada**.
3. Tu cliente usa tu **clave privada** para responder correctamente.

Si el servidor puede verificar esa respuesta con tu **clave pública**, entonces concluye:

✅ “Este cliente realmente posee la clave privada asociada. Le doy acceso.”

### Importante

* La **clave privada no se envía**.
* No se envía “la solución” como texto plano.
* Normalmente se usa una firma (signature) sobre datos del intercambio.

**Resultado:** autenticación fuerte sin compartir secreto reutilizable (como contraseña).

---

## 5.4 Challenge

## ¿Cómo es realmente el “desafío” (challenge) que envía el servidor?

En la sección anterior vimos que el servidor envía un *challenge* para que el cliente demuestre que posee la clave privada.

Ahora vamos a explicar **qué es ese desafío realmente y qué contiene**, a grandes rasgos y sin entrar en matemática pesada.

---

# 1) Primero: ya existe un canal cifrado

Antes de llegar al challenge, cliente y servidor ya realizaron el:

* Intercambio de claves (Key Exchange – KEX)
* Generación de una clave de sesión

Esto significa que:

* La comunicación ya está cifrada.
* Nadie puede ver el contenido del challenge desde afuera.

---


## SSH – ¿Cómo se crea el canal cifrado antes del challenge?

---

### 1) Punto de partida: todavía NO hay cifrado

Cuando ejecutás:

```bash
ssh usuario@servidor
```

En ese instante inicial:

* Cliente y servidor todavía no comparten ninguna clave.
* No existe aún un canal cifrado.
* Están en la fase de negociación.

El primer objetivo es:

👉 Crear una **clave secreta compartida** sin enviarla directamente por la red.

---

### 2) Negociación de algoritmos

Primero, cliente y servidor intercambian listas de algoritmos soportados:

* Algoritmos de Key Exchange (ej: curve25519-sha256)
* Algoritmos de cifrado simétrico (ej: aes256-ctr, chacha20-poly1305)
* Algoritmos de integridad (MAC)
* Algoritmos de host key

Ambos eligen la opción más fuerte que tengan en común.

Todavía no hay autenticación del usuario.

---

### 3) Key Exchange (KEX) – El corazón del proceso

Aquí ocurre la parte crítica.

SSH usa normalmente:

* Diffie-Hellman (DH)
* ECDH (Elliptic Curve Diffie-Hellman)
* Curve25519

Todos cumplen el mismo objetivo:

👉 Permitir que ambos lados calculen la misma clave secreta sin transmitirla.

---

### 4) Explicación simplificada de Diffie-Hellman

Imaginemos:

* Cliente elige un número secreto A
* Servidor elige un número secreto B

Ambos intercambian versiones públicas derivadas matemáticamente de esos secretos.

Luego, mediante una operación matemática:

* Cliente usa su secreto A + dato público del servidor
* Servidor usa su secreto B + dato público del cliente

Ambos llegan al mismo resultado final:

👉 Una clave secreta compartida

Un atacante que observe el tráfico:

❌ No puede reconstruir esa clave secreta
(si el algoritmo es fuerte y no está roto)

---

### 5) Derivación de la clave de sesión

El resultado del KEX no se usa directamente.

Se pasa por funciones hash para derivar:

* Clave de cifrado cliente → servidor
* Clave de cifrado servidor → cliente
* Claves de integridad (MAC)
* Claves adicionales si son necesarias

Ahora sí:

👉 Existe una clave simétrica compartida.

---

### 6) Activación del canal cifrado

A partir de este momento:

* Todo el tráfico se cifra con un algoritmo simétrico.
* Ejemplos: AES, ChaCha20.

¿Por qué simétrico?

Porque es:

* Mucho más rápido.
* Mucho más eficiente.
* Ideal para cifrar grandes volúmenes de datos.

---

### 7) Autenticación del servidor (Host Key Verification)

Durante el proceso de KEX, el servidor firma parte del intercambio con su **host private key**.

El cliente verifica esa firma usando la host public key.

Si la clave no coincide con la almacenada en `known_hosts`, se genera advertencia.

Esto protege contra ataques Man-in-the-Middle.

---

### 8) Perfect Forward Secrecy (PFS)

Los KEX modernos tienen una propiedad clave:

✅ Perfect Forward Secrecy

Esto significa que:

* Cada sesión genera claves nuevas.
* Si en el futuro roban la clave privada del servidor,
  no podrán descifrar sesiones anteriores capturadas.

---

### 9) En qué momento estamos respecto al challenge

Recién ahora:

✔ Ya existe una clave simétrica compartida.
✔ Ya hay un canal cifrado.
✔ El servidor ya fue autenticado.

Recién en este punto comienza la autenticación del usuario:

* Password
* Public Key
* Keyboard-interactive

Y por eso el challenge de autenticación viaja ya dentro de un canal cifrado.

---

### 10) Resumen

El proceso:

1️⃣ Negociación de algoritmos
2️⃣ Key Exchange asimétrico
3️⃣ Derivación de clave simétrica
4️⃣ Activación del canal cifrado
5️⃣ Autenticación del servidor
6️⃣ Autenticación del usuario





---

# 2) El challenge NO es un número aleatorio simple

Mucha gente imagina que el servidor manda algo como:

> “Decime cuánto es 12345 cifrado”

Pero en realidad el challenge es más complejo.

El servidor construye un bloque de datos que incluye:

* 🔐 El hash del intercambio inicial (handshake)
* 🧩 Información de la sesión actual
* 👤 El nombre del usuario que intenta autenticarse
* 🔑 El tipo de clave que se está usando (ej: ed25519, rsa)

Es decir:

El challenge está ligado **a esa sesión específica**.

---

# 3) ¿Qué hace el cliente con ese challenge?

Cuando el servidor envía ese bloque de datos:

1. El cliente lo recibe.
2. Lo procesa internamente.
3. Lo firma digitalmente con su **clave privada**.

El resultado es una **firma criptográfica**.

⚠️ Muy importante:

* No se envía la clave privada.
* No se envía ningún secreto reutilizable.
* Solo se envía la firma.

---

# 4) ¿Qué hace el servidor con la respuesta?

El servidor toma:

* La firma enviada por el cliente
* La clave pública guardada en `authorized_keys`

Y verifica matemáticamente si:

> Esa firma solo pudo haber sido generada con la clave privada correspondiente.

Si la verificación es correcta:

✅ El cliente posee la clave privada.

Si no es válida:

❌ Se rechaza la autenticación.

---

# 5) ¿Por qué esto evita ataques de repetición (Replay)?

Porque el challenge:

* Está ligado a esa sesión.
* Incluye datos únicos del handshake.
* Cambia en cada conexión.

Entonces, aunque alguien capturara la firma (lo cual ya es difícil porque está cifrado), no podría reutilizarla en otra sesión.

---

# 6) Resumen

El challenge es:

👉 Un conjunto de datos únicos de la sesión.
👉 Que el cliente debe firmar con su clave privada.
👉 Para demostrar matemáticamente que la posee.

No se comparte ningún secreto reutilizable.
No se transmite la clave privada.
La autenticación se basa en criptografía asimétrica fuerte.

---

---


# 6) ¿Por qué entonces “solo ingreso la passphrase una vez”?

Acá hay un detalle muy importante y común:

## 6.1 Sin ssh-agent

Si no usás `ssh-agent`, puede que te pida la passphrase cada vez que uses la clave (según tu entorno).

## 6.2 Con ssh-agent

Con `ssh-agent`, vos desbloqueás la clave privada una vez y queda cargada en memoria durante la sesión.

Ejemplo conceptual:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

A partir de ahí:

* Podés conectar a múltiples servidores sin reingresar la passphrase.

---

# 7) ¿Qué pasa si alguien gana acceso físico a mi PC?

* Si tu sesión está abierta y tu `ssh-agent` tiene la clave cargada, hay riesgo.
* Si cerrás sesión o bloqueás el equipo, mitigás.
* Si alguien roba el archivo de clave privada **y no tiene tu passphrase**, le costará mucho más usarla.

**Buenas prácticas:**

* passphrase larga
* bloquear pantalla
* cerrar sesión al terminar
* usar llaves modernas (ed25519)

---

# 8) Resumen mental (ultra claro)

✅ SSH verifica al servidor con **host keys** (known_hosts)
✅ El servidor te verifica a vos con **tu clave pública** (authorized_keys)
✅ Vos probás que sos vos firmando un desafío con **tu clave privada**
✅ La clave privada nunca sale de tu equipo
✅ La passphrase protege la clave privada (y con ssh-agent no la repetís todo el tiempo)

---

# 9) Qué deberías recordar para pentesting (en una línea)

En auditorías, **Public Key Auth** suele ser más seguro que password, pero cuando está mal administrado puede exponerse por:

* claves privadas robadas en backups o shares (ej: Rsync abierto)
* permisos inseguros en `.ssh/`
* llaves sin passphrase
* `authorized_keys` mal controlado

---

## 10) Mini-glosario

* **Host key**: clave del servidor (identidad del servidor)
* **known_hosts**: archivo del cliente con host keys confiables
* **authorized_keys**: archivo del servidor con claves públicas autorizadas
* **Private key**: secreto del cliente
* **Public key**: parte compartible
* **Passphrase**: contraseña que desbloquea tu clave privada
* **ssh-agent**: “llavero” en memoria para no reingresar passphrase todo el tiempo

---

# Configuración por defecto (sshd_config)

Archivo principal:

El archivo [sshd_config](https://www.ssh.com/academy/ssh/sshd_config) responsable del servidor OpenSSH, solo incluye algunas de las opciones predeterminadas. Sin embargo incluye el reenvío X11, que contenía una vulnerabilidad de inyección de comandos en la versión 7.2p1 de OpenSSH de 2016.

```
/etc/ssh/sshd_config
```

Ejemplo típico de configuración activa:

```bash
cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

```
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
```

La mayoría de opciones suelen estar comentadas y requieren configuración manual.

---



# SSH – Configuraciones Peligrosas en sshd_config 

A continuación se presenta una tabla ampliada con las configuraciones más sensibles de SSH, su descripción técnica y el impacto desde la perspectiva de seguridad ofensiva.

---

| Setting                        | Qué Hace Técnicamente                                                | Riesgo de Seguridad                                               | Impacto en Pentesting                                                           | Nivel de Riesgo |
| ------------------------------ | -------------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------- |
| **PasswordAuthentication yes** | Permite autenticación mediante contraseña en lugar de clave pública. | Habilita ataques de fuerza bruta y password spraying.             | Ataques con Hydra, Medusa, Ncrack, spraying con credenciales filtradas.         | 🔴 Alto         |
| **PermitEmptyPasswords yes**   | Permite autenticarse con cuentas que tengan contraseña vacía.        | Acceso inmediato si existe un usuario mal configurado.            | Enumeración de usuarios + login directo sin credenciales.                       | 🔴 Crítico      |
| **PermitRootLogin yes**        | Permite login directo como root vía SSH.                             | Si se compromete root, se obtiene control total del sistema.      | Fuerza bruta directa contra root, uso de credenciales reutilizadas.             | 🔴 Crítico      |
| **Protocol 1**                 | Permite el uso del protocolo SSH versión 1.                          | Vulnerable a ataques MITM y debilidades criptográficas conocidas. | Downgrade attacks, explotación de debilidades antiguas.                         | 🔴 Crítico      |
| **X11Forwarding yes**          | Permite redirección de aplicaciones gráficas vía SSH.                | Puede introducir vectores de inyección o abuso del canal X11.     | Posible ejecución remota de aplicaciones gráficas, abuso de display forwarding. | 🟠 Medio        |
| **AllowTcpForwarding yes**     | Permite redirección de puertos TCP a través del túnel SSH.           | Facilita pivoting y evasión de segmentación de red.               | Creación de túneles para acceder a servicios internos (pivoting).               | 🔴 Alto         |
| **PermitTunnel yes**           | Permite creación de interfaces de red tun/tap sobre SSH.             | Puede crear túneles de red completos entre hosts.                 | Pivoting avanzado, bypass de firewalls internos.                                | 🔴 Alto         |
| **DebianBanner yes**           | Muestra información específica del sistema en el banner.             | Divulga información del sistema operativo y versión.              | Fingerprinting más preciso del sistema objetivo.                                | 🟡 Bajo         |


# SSH – Riesgos de Permitir Autenticación por Contraseña

Cuando `PasswordAuthentication` está habilitado, el servidor SSH permite el ingreso mediante usuario y contraseña.  

Esto abre la puerta a ataques como:

- 🔴 Fuerza bruta
- 🔴 Password spraying
- 🔴 Reutilización de credenciales filtradas

---

## 🧠 ¿Por qué funciona tan bien para un atacante?

Porque los humanos tendemos a:

- Usar contraseñas simples.
- Reutilizar contraseñas.
- Agregar solo números o símbolos al final (ej: `Password1!`).
- Hacer pequeñas variaciones de contraseñas comunes.

Los atacantes explotan esto usando:

- Diccionarios de contraseñas comunes.
- Reglas de mutación (ej: agregar `123`, `!`, año actual).
- Listas filtradas de breaches anteriores.

El objetivo no es probar todas las combinaciones posibles, sino aprovechar patrones humanos predecibles.

---

## 🛡️ Mitigación Recomendada

- Deshabilitar `PasswordAuthentication`.
- Usar autenticación por clave pública.
- Implementar rate limiting (Fail2Ban).
- Aplicar MFA cuando sea posible.

---

> La autenticación por contraseña no es inherentemente insegura, pero combinada con exposición a Internet y contraseñas débiles, se convierte en uno de los vectores más explotados en infraestructuras Linux.

[Guía de hardening](https://www.ssh-audit.com/hardening_guides.html)

---

# Fingerprinting de SSH

Herramienta útil:

```
ssh-audit
```

[ssh-audit](https://github.com/jtesta/ssh-audit)  


Permite identificar:

* Versión del servidor
* Algoritmos de intercambio de claves
* Algoritmos débiles
* Métodos de autenticación disponibles


```bash
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py 10.129.14.132

# general
(gen) banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
(gen) software: OpenSSH 8.2p1
(gen) compatibility: OpenSSH 7.4+, Dropbear SSH 2018.76+
(gen) compression: enabled (zlib@openssh.com)                                   

# key exchange algorithms
(kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4, Dropbear SSH 2018.76                            
(kex) curve25519-sha256@libssh.org          -- [info] available since OpenSSH 6.5, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp256                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp384                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp521                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) diffie-hellman-group-exchange-sha256 (2048-bit) -- [info] available since OpenSSH 4.4
(kex) diffie-hellman-group16-sha512         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73
(kex) diffie-hellman-group18-sha512         -- [info] available since OpenSSH 7.3
(kex) diffie-hellman-group14-sha256         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73

# host-key algorithms
(key) rsa-sha2-512 (3072-bit)               -- [info] available since OpenSSH 7.2
(key) rsa-sha2-256 (3072-bit)               -- [info] available since OpenSSH 7.2
(key) ssh-rsa (3072-bit)                    -- [fail] using weak hashing algorithm
                                            `- [info] available since OpenSSH 2.5.0, Dropbear SSH 0.28
                                            `- [info] a future deprecation notice has been issued in OpenSSH 8.2: https://www.openssh.com/txt/release-8.2
(key) ecdsa-sha2-nistp256                   -- [fail] using weak elliptic curves
                                            `- [warn] using weak random number generator could reveal the key
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(key) ssh-ed25519                           -- [info] available since OpenSSH 6.5
...SNIP...
```

Lo primero que vemos en las primeras líneas del resultado es el banner que revela la versión del servidor `Open SSH`. Las versiones anteriores presentaban vulnerabilidades, como [CVE-2020-14145](https://www.cvedetails.com/cve/CVE-2020-14145/) que permitían al atacante realizar un ataque de intermediario (Man in the middle) durante el primer intento de conexión.

También podemos pedir el resultado detallado de la configuración de la conexión con el servidor que suele proporcionar información importante, como los métodos de autenticación:

```bash
ssh -v user@ip


OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config 
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
```

Ejemplo de autenticaciones permitidas:

```
Authentications that can continue: publickey,password,keyboard-interactive
```

Podemos forzar método específico:

```
ssh -o PreferredAuthentications=password usuario@host



OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: password

cry0l1t3@10.129.14.132's password:
```

Se recomienda configurar un servidor para practicar con las distintas configuraciones en nuestra VM. 

Durante un test de penetración es común encontrarse con el **banner del servicio SSH** al conectarnos al puerto 22.

Por defecto, el banner revela:

1. 📌 La versión del protocolo SSH soportado.
2. 📌 La versión del servidor SSH en ejecución.

---

## 🔎 Estructura del Banner

Formato típico:
```
SSH-<versión_protocolo>-<software>_<versión>
```

---

## 🧠 Ejemplos

### 🔹 `SSH-1.99-OpenSSH_3.9p1`

- `1.99` → Indica compatibilidad con **SSH-1 y SSH-2**.
- `OpenSSH_3.9p1` → Servidor OpenSSH versión 3.9p1.

⚠️ SSH-1 es obsoleto y vulnerable, por lo que su compatibilidad representa un riesgo potencial.

---

### 🔹 `SSH-2.0-OpenSSH_8.2p1`

- `2.0` → Solo acepta **SSH-2**.
- `OpenSSH_8.2p1` → Versión moderna del servidor.

✅ Indica uso exclusivo del protocolo seguro SSH-2.

---

## 🎯 Relevancia en Pentesting

El banner permite:

- Identificar versiones vulnerables.
- Detectar soporte de protocolos obsoletos.
- Buscar exploits específicos para la versión detectada.
- Evaluar exposición innecesaria de información.

---

> El banner de SSH es una fuente temprana de fingerprinting que puede orientar la fase inicial de reconocimiento.

---

# Rsync

## ¿Qué es?

Rsync es una herramienta eficiente para copiar archivos local y remotamente.

* Puerto por defecto: **TCP 873**
* Usa algoritmo delta-transfer
* Muy utilizado para backups y sincronización

Puede operar:

* En modo daemon (873)
* Sobre SSH

---

## Enumeración de Rsync

Detección con Nmap:

```
nmap -sV -p 873 target
```

Enumerar módulos compartidos:

```
nc target 873
#list
```

Listar contenido:

```
rsync -av --list-only rsync://target/module
```

Si el share es anónimo, puede permitir descarga sin autenticación.

Riesgos comunes:

* Exposición de backups
* Archivos de configuración
* Claves privadas SSH
* Reutilización de credenciales

---

# R-Services

## ¿Qué son?

Conjunto de servicios antiguos para acceso remoto en Unix.

Puertos comunes:

* 512 (rexec)
* 513 (rlogin)
* 514 (rsh)

Transmisión sin cifrado.

Reemplazados por SSH debido a graves problemas de seguridad.

---

## Comandos principales

| Comando | Puerto | Descripción      |
| ------- | ------ | ---------------- |
| rlogin  | 513    | Login remoto     |
| rsh     | 514    | Shell remoto     |
| rexec   | 512    | Ejecución remota |
| rcp     | 514    | Copia remota     |

---

# Control de Confianza: hosts.equiv y .rhosts

Archivos críticos:

* /etc/hosts.equiv (global)
* ~/.rhosts (por usuario)

Formato típico:

```
usuario 10.0.0.5
+ 10.0.0.10
+ +
```

El uso de `+` como wildcard puede permitir autenticación sin contraseña.

Esto puede derivar en:

* Login sin credenciales
* Ejecución remota
* Movimiento lateral

---

# Enumeración de R-Services

Escaneo:

```
nmap -sV -p 512,513,514 target
```

Login:

```
rlogin target -l usuario
```

Enumeración de usuarios activos:

```
rwho
rusers -al target
```

---

# Conclusiones Finales

Los protocolos de administración remota representan uno de los vectores más críticos en un entorno Linux.

Desde la perspectiva ofensiva:

* Siempre enumerar servicios expuestos
* Analizar versiones y banners
* Buscar autenticación débil
* Probar reutilización de credenciales
* Revisar configuraciones inseguras

Desde la perspectiva defensiva:

* Deshabilitar protocolos obsoletos
* Usar únicamente SSH-2
* Deshabilitar autenticación por contraseña si es posible
* Implementar MFA
* Limitar acceso por IP
* Monitorear intentos de login

Como profesionales de seguridad, debemos dominar tanto el funcionamiento técnico como las posibles vías de abuso de estos protocolos.
