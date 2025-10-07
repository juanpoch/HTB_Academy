# Introducción a Windows Privilege Escalation


## Foothold

* Contar con una sesión interactiva (cmd/powershell/remote shell, RDP local, shell remoto) como un usuario con privilegios limitados.
* Objetivo típico: escalar a un miembro del grupo **Local Administrators** o **NT AUTHORITY\SYSTEM**.

---

##  Motivos para Escalar privilegios

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

## Escenarios prácticos

* **Escenario 1: Restricciones de red** — usar VLAN imprimidora con puertos 80/443/445 abiertos, volcar LSASS, exfiltrar a SMB montado.
* **Escenario 2: Openshares** — montar VHDX remotos, extraer hives SYSTEM/SAM/SECURITY y extraer hashes.
* **Escenario 3: Buscar credenciales y abusar privilegios** — usar credenciales de DB, habilitar `xp_cmdshell`, comprobar `SeImpersonatePrivilege` y usar Juicy Potato para elevar.


---

---


## Lista de herramientas

| Herramienta                                 |             Tipo | Descripción rápida                                                                                                                               |
| ------------------------------------------- | ---------------: | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Seatbelt**                                |        C# / .NET | Escanea el host realizando multitud de checks locales (perm, servicios, tareas, registro, credenciales). Útil para obtener "big picture" rápido. |
| **winPEAS**                                 |  Script (EXE/PS) | Gran script que busca rutas potenciales para escalar privilegios en Windows. Devuelve mucha información (útil + ruido).                          |
| **PowerUp**                                 |       PowerShell | Script para encontrar vectores comunes (permiso de servicios, tareas, ACLs) y explotar algunas fallas básicas.                                   |
| **SharpUp**                                 |        C# / .NET | Versión compilada de PowerUp. Buena cuando no podés ejecutar scripts PowerShell o querés binario.                                                |
| **JAWS**                                    |       PowerShell | Enumerador escrito compatible con PowerShell 2.0 — útil en entornos legacy.                                                                      |
| **SessionGopher**                           |       PowerShell | Extrae/descifra sesiones guardadas de clientes RDP/Putty/WinSCP/FileZilla, etc. Muy valioso para credenciales residuales.                        |
| **Watson**                                  |             .NET | Identifica KBs faltantes y sugiere exploits públicos para escalado local. Buen complemento a WES-NG.                                             |
| **LaZagne**                                 | Python / binario | Recupera contraseñas guardadas localmente (browsers, apps, RDP, Wi‑Fi, herramientas sysadmin). Muy potente — detectado por AV.                   |
| **WES‑NG (Windows Exploit Suggester - NG)** |           Python | Analiza `systeminfo` y sugiere CVEs/exploits aplicables para la versión de Windows.                                                              |
| **Sysinternals Suite**                      |         Binaries | Herramientas oficiales (AccessChk, PsService, PipeList, ProcDump, Process Explorer, etc.) — imprescindibles para enumeración y análisis forense. |

---

## 2) Dónde y cómo obtener/usar las herramientas

* **Preferible compilar desde fuente** cuando se pueda (menos detección AV, más control).
* Si usás binarios precompilados: verifica firma/archivo y ten en cuenta detecciones. Repositorios oficiales en GitHub (Seatbelt, SharpUp, LaZagne, winPEAS).
* En entornos con restricciones, `C:\Windows\Temp` suele ser writeable por BUILTIN\Users y funciona para subir binarios temporales.
* Recomendación: mantener una carpeta `C:\Tools` en las máquinas laboratorio con binarios aprobados para las prácticas.

---

## 3) Buenas prácticas al usar herramientas

1. **Antes**: entender qué hace la herramienta — leer el código o documentación mínima (evita false positives/noise).
2. **Filtrar la salida**: las herramientas devuelven mucho; crear filtros/regex para destacar hallazgos relevantes (service path, weak ACL, credenciales en claro).
3. **Manual primero**: intentar comprobaciones manuales básicas (wmic, schtasks, whoami) antes de lanzar scripts masivos.
4. **Registro**: copiar salida relevante (no todo) a `loot/` con timestamp y contexto.
5. **Seguridad legal**: en entornos cliente, confirmar autorización para ejecutar herramientas intrusivas (dump de LSASS, Mimikatz).

---

## 4) Riesgos: detección AV/EDR y estabilidad del sistema

* Muchas herramientas son **falsamente o verdaderamente detectadas** por AV/EDR. Ejemplo: LaZagne precompilado en VirusTotal: **47/70** detecciones (hash: `ed2f501408a7a6e1a854c29c4b0bc5648aaa8612432df829008931b3e34bf56`, upload: `2021-06-20`, tamaño: `6.33 MB`). Puedes ver el escaneo en la imagen adjunta.

  * Consecuencia: ejecutarlas en entornos con defender/EDR activo provocará alertas, bloqueos o respuestas (kernel quarantines, reinicios, bloqueo de proceso).
  * Solución en laboratorios: usar binarios aprobados por el instructor o compilar localmente. En ejercicios contra defensas reales — técnicas de evasión (obfuscation, recompile, signed loaders) caen en módulos posteriores.

---

## 5) Estrategias cuando no podés ejecutar herramientas

* **Comprobaciones nativas**: `whoami`, `systeminfo`, `wmic`, `schtasks`, `reg query`, `icacls`, `Get-Service` / `Get-WmiObject`.
* **Extracción no binaria**: leer ficheros .rdp/.config, montar VHDX desde network share, exfiltrar hives (SYSTEM/SAM) si es posible.
* **Compilar en remoto**: si tenés acceso RDP/Visual Studio en la máquina, compilar utilitarios (por ejemplo SharpUp) directamente en la host objetivo para evadir AV genérico.

---

## 6) Recomendaciones de uso por herramienta

* **Seatbelt**: ideal para un primer barrido. Revisa resultados y descarta líneas ignorables.
* **winPEAS**: usar con parámetros para reducir ruido (`winPEAS.bat quiet` / filtrar secciones). Revisar manualmente resultados sensibles (creds, permisos).
* **PowerUp / SharpUp**: centrarse en la sección de servicios/ACLs y probar PoC manuales antes de ejecutar exploits automáticos.
* **SessionGopher / LaZagne**: tratar como fuente de credenciales - validar credenciales en servicios locales antes de confiar ciegamente.
* **Sysinternals**: AccessChk para revisar ACLs, ProcDump/Taskmgr para dumps de procesos (si está permitido).
* **WES‑NG / Watson**: buen punto de partida para descubrir parches faltantes — validar manualmente si un exploit es aplicable.

---

## 7) Lista corta de comandos nativos imprescindibles

```powershell
whoami /all
systeminfo
wmic service get name,displayname,pathname,startmode
schtasks /query /fo LIST /v
icacls "C:\Program Files\App\app.exe"
reg query HKLM\SYSTEM\CurrentControlSet\Services\ -v ImagePath
Get-ChildItem -Path C:\ -Include *.config,*.ps1,*.rdp -Recurse -ErrorAction SilentlyContinue
```

---




