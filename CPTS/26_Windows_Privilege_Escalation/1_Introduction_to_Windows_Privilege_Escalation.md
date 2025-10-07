# Introducción a Windows Privilege Escalation


## Foothold

* Contar con una sesión interactiva (cmd/powershell/remote shell, RDP local, shell remoto) como un usuario con privilegios limitados.
* Objetivo típico: escalar a **Local Administrators** o **NT AUTHORITY\SYSTEM**.

---

##  Escalar privilegios

1. Revisar y extraer información que sólo está disponible con permisos elevados (credenciales, registros, backups).
2. Habilitar persistencia (servicios, tareas programadas, cuentas locales).
3. Facilitar movimiento lateral (credenciales de alto privilegio, hashes para pass‑the‑hash).
4. Para evaluaciones de "gold image" o «workstation breakout» donde el objetivo es comprobar configuraciones por defecto.

---

## Vectores comunes

* **Unquoted Service Path**
* **Weak Service Permissions** (modify/replace binary)
* **Insecure File / Folder ACLs** (lectura de configs con credenciales)
* **Scheduled Tasks** editables o con passwords en claro
* **DLL Hijacking / Binary Planting**
* **AlwaysInstallElevated** (MSI abuse)
* **SeImpersonatePrivilege / Token Impersonation** (Rotten/Juicy/SharpPotato)
* **Credential Dumps** (LSASS memory, registry hives, VHD mounts)
* **Unpatched kernel / drivers** (exploits locales)
* **Misconfigured Services / Shares**

---

## Herramientas útiles

### A) En entornos con internet / posibilidad de subir binarios

* WinPEAS, PowerUp, Seatbelt, Snaffler
* Mimikatz (cuando es legal/permitido en lab)
* Juicy Potato / RottenPotatoNG / SharpUp
* Impacket (secretsdump.py, psexec.py)
* Snaffler / Sysinternals (Autoruns, ProcExplorer)

### B) En entornos *aislados* (sin internet, USB bloqueado)

* Conocer y usar comandos nativos:

  * `whoami /priv`, `whoami /groups`, `systeminfo`, `net user`
  * `wmic service get name,displayname,pathname,startmode`
  * `schtasks /query /fo LIST /v`
  * PowerShell: `Get-Service`, `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\* -Name ImagePath -ErrorAction SilentlyContinue`
* Capacidad para compilar o transferir fuentes ligeras si se permite mediante RDP o carpetas compartidas.

---

## Comprobaciones manuales (PowerShell / CMD) — Checklist rápido

> Ejecutar desde la cuenta comprometida y anotar resultados.

### Información general

```powershell
whoami /all
systeminfo
net user
net localgroup administrators
```

### Servicios

```powershell
wmic service get name,displayname,pathname,startmode
# ó PowerShell:
Get-WmiObject Win32_Service | select Name, DisplayName, PathName, StartMode
```

* Buscar `ImagePath` con espacios sin comillas.
* Verificar permisos del binario (puede ser sobrescrito por la cuenta actual?).

### Tareas programadas

```cmd
schtasks /query /fo LIST /v
```

* Buscar rutas a scripts o comandos editables, o tareas que ejecutan con cuentas de alto privilegio.

### Archivos / Shares / Credenciales

```powershell
Get-ChildItem -Path C:\ -Include *.config,*.xml,*.ps1,*.rdp -Recurse -ErrorAction SilentlyContinue
# Buscar palabras clave: password, pwd, pass, credential, token, connectionString
```

### Memoria y LSASS (si está permitido en el lab)

* Verificar privilegios necesarios (`SeDebugPrivilege`) antes de intentar dump.
* Métodos: procdump, comsvcs, taskmgr (Dependiendo de permisos y reglas del laboratorio).

---

## Escenarios prácticos

* **Escenario 1: Restricciones de red** — usar VLAN imprimidora con puertos 80/443/445 abiertos, volcar LSASS, exfiltrar a SMB montado.
* **Escenario 2: Openshares** — montar VHDX remotos, extraer hives SYSTEM/SAM/SECURITY y extraer hashes.
* **Escenario 3: Buscar credenciales y abusar privilegios** — usar credenciales de DB, habilitar `xp_cmdshell`, comprobar `SeImpersonatePrivilege` y usar Juicy Potato para elevar.

Cada escenario debe acompañarse de pasos reproducibles en laboratorios HTB; aquí quedan como guiones de ejercicios.

---

## Ejercicios propuestos

1. **Nivel Básico**: Identificar permisos de servicio con `wmic` y localizar un `unquoted service path` vulnerable. Probar PoC localmente.
2. **Nivel Intermedio**: Encontrar un share abierto con VHDX, montar el VHDX y extraer hives.
3. **Nivel Intermedio-Avanzado**: Encontrar y usar `SeImpersonatePrivilege` con una versión compilada de Juicy Potato (si la plataforma lo permite).
4. **Nivel Avanzado**: Realizar dump de LSASS en un entorno restringido y exfiltrar al atacante a través de un SMB montado.

Para cada ejercicio: objetivos, comandos mínimos, outputs esperados y checklist de mitigación.

---

## Mitigaciones

* Revisar y aplicar comillas en rutas de servicios (`"C:\Program Files\MiServicio\bin.exe"`).
* Restringir permisos de escritura en directorios de servicios y binarios.
* Auditar y limitar cuentas con **SeImpersonatePrivilege** y otras capacidades peligrosas.
* Evitar backups/VMs accesibles públicamente en shares; cifrar y limitar acceso.
* Deshabilitar `xp_cmdshell` cuando no sea necesario; gestionar credenciales en vaults.
* Monitorizar: creación de servicios, cambios en tareas programadas, procesos que acceden a LSASS.

---


## 12. Recursos y referencias

* WinPEAS, PowerUp, JuicyPotato, RottenPotatoNG, Mimikatz, Impacket
* Documentación Microsoft sobre servicios, tareas programadas y permisos
* PortSwigger / Offensive Security writeups y labs para práctica adicional

---


