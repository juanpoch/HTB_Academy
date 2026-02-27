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

Vamos con el flujo completo, explicado como si fuera la primera vez.

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

```
/etc/ssh/sshd_config
```

Ejemplo típico de configuración activa:

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

# Configuraciones Peligrosas en SSH

Algunas opciones inseguras incluyen:

| Setting                    | Riesgo                          |
| -------------------------- | ------------------------------- |
| PasswordAuthentication yes | Permite ataques de fuerza bruta |
| PermitEmptyPasswords yes   | Permite contraseñas vacías      |
| PermitRootLogin yes        | Acceso directo como root        |
| Protocol 1                 | Uso de cifrado obsoleto         |
| X11Forwarding yes          | Posibles vectores adicionales   |
| AllowTcpForwarding yes     | Permite pivoting                |

En pentesting, estas configuraciones pueden facilitar:

* Fuerza bruta
* Password spraying
* Pivoting interno
* Escalada lateral

---

# Fingerprinting de SSH

Herramienta útil:

```
ssh-audit
```

Permite identificar:

* Versión del servidor
* Algoritmos de intercambio de claves
* Algoritmos débiles
* Métodos de autenticación disponibles

Ejemplo de autenticaciones permitidas:

```
Authentications that can continue: publickey,password,keyboard-interactive
```

Podemos forzar método específico:

```
ssh -o PreferredAuthentications=password usuario@host
```

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
