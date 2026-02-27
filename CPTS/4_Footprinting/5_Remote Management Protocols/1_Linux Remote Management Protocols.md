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

SSH (Secure Shell) es el protocolo estándar para administración remota segura en sistemas Linux.

* Puerto por defecto: **TCP 22**
* Protocolo cifrado
* Permite ejecución remota de comandos
* Transferencia de archivos (SCP/SFTP)
* Port forwarding y túneles

SSH reemplazó a protocolos inseguros como Telnet y R-Services.

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

---

# Autenticación por Clave Pública

## Flujo de autenticación

1. El servidor envía su **host key pública** al cliente.
2. El cliente valida la identidad del servidor.
3. El cliente demuestra que posee la **clave privada** correspondiente a su clave pública registrada en el servidor.

La clave privada:

* Se almacena únicamente en el equipo del usuario.
* Está protegida por una passphrase.
* Nunca se envía al servidor.

Este mecanismo evita enviar contraseñas a través de la red.

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
