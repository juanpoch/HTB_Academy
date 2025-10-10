# Enumeración inicial

Durante una evaluación, podemos obtener una shell con privilegios reducidos en un host Windows (unido a dominio o no) y necesitaremos realizar escalada de privilegios para ampliar nuestro acceso. Comprometer totalmente el host puede permitirnos acceder a archivos compartidos sensibles, capturar tráfico para obtener más credenciales, u obtener credenciales que nos ayuden a avanzar o incluso escalar directamente a Domain Admin en un entorno Active Directory. Podemos escalar privilegios a uno de los siguientes, según la configuración del sistema y los datos que encontremos:

* La cuenta altamente privilegiada **NT AUTHORITY\SYSTEM**, o [**LocalSystem**](https://learn.microsoft.com/es-es/windows/win32/services/localsystem-account), que tiene más privilegios que una cuenta de administrador local y se usa para ejecutar la mayoría de servicios de Windows. Es la cuenta que utiliza el `SCM`. El subsistema de seguridad no reconoce esta cuenta, por lo que no tiene contraseña.

 `Nota 1`:`Service Control Manager`: El Administrador de control de servicios en Windows es un componente del sistema operativo responsable de gestionar los servicios del sistema (tanto de Windows como de aplicaciones de terceros). Su función principal es iniciar, detener, pausar, reanudar y configurar los servicios que se ejecutan en segundo plano. [SCM](https://learn.microsoft.com/es-es/windows/win32/services/service-control-manager)  

 `Nota 2`: El subsistema de seguridad de Windows es el componente del sistema operativo encargado de controlar la autenticación, autorización y auditoría de usuarios y procesos. Sus principales componentes son:
 | Componente                  | Función principal                               |
| --------------------------- | ----------------------------------------------- |
| **LSASS**                   | Autenticación y gestión de seguridad            |
| **SRM**                     | Control de acceso a recursos                    |
| **SAM**                     | Base de datos de cuentas locales                |
| **Winlogon**                | Manejo del inicio de sesión                     |
| **Authentication Packages** | Métodos de autenticación (NTLM, Kerberos, etc.) |
| **LSA Policy DB**           | Configuración y políticas de seguridad          |

 
 
* La **cuenta local Administrador** incorporada. Algunas organizaciones la deshabilitan, pero muchas no. No es raro ver la misma contraseña de administrador local reutilizada en varios sistemas.
* Otra cuenta local que sea miembro del grupo **Administradores locales**. Cualquier cuenta en ese grupo tendrá los mismos privilegios que la cuenta Administrador incorporada.
* Un usuario de dominio estándar (sin privilegios) que forma parte del **grupo Administradores locales**.
* Un **domain admin** (altamente privilegiado en AD) que sea miembro del grupo Administradores locales.

La enumeración es la clave para la escalada de privilegios. Cuando obtenemos acceso inicial a la máquina, es vital obtener conciencia situacional y descubrir detalles sobre versión del SO, nivel de parches, software instalado, privilegios actuales, membresías de grupos y más. A continuación vemos los puntos clave que deberíamos revisar después de obtener acceso inicial. Esto no es una lista exhaustiva; las herramientas y scripts cubren muchos más puntos. No obstante, es esencial saber realizar estas tareas manualmente, especialmente si estamos en un entorno donde no podemos cargar herramientas por restricciones de red, falta de internet o protecciones.

Esta [referencia de comandos](https://learn.microsoft.com/es-es/windows-server/administration/windows-commands/windows-commands) de Windows es útil para realizar tareas de enumeración manual.

---

## Puntos de datos clave

* **OS name:** Saber si es estación de trabajo o servidor y la versión (Windows 7, 10, Server 2008/2012/2016/2019...) nos da idea de las herramientas disponibles (p. ej. versión de PowerShell) y si existen exploits públicos aplicables.

* **Versión:** Como con el nombre, puede haber exploits públicos para una versión concreta. Los exploits de sistema pueden inestabilizar o causar crash; precaución en entornos productivos.

* **Running Services:** Importante especialmente aquellos que corren como **NT AUTHORITY\SYSTEM** o con cuenta admin. Un servicio mal configurado o vulnerable ejecutado en contexto privilegiado puede ser una escalada sencilla.

[Versiones de Windows](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions)

---

## Información del sistema

Ver la información del sistema nos da la versión exacta del sistema operativo, hardware, programas instalados y actualizaciones de seguridad. Esto ayuda a acotar parches faltantes y CVEs aplicables. Usar `tasklist` para ver procesos en ejecución muestra qué aplicaciones están corriendo.

### Tasklist

```
C:\htb> tasklist /svc
```

(Explicación: muestra procesos y servicios asociados a cada PID, útil para detectar qué ejecuta cada svchost.exe.)

[tasklist doc](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist)

Fijarse en procesos no estándar (por ejemplo, FileZilla Server) para investigar versión o configuraciones. También procesos como `MsMpEng.exe` (Windows Defender) nos indican protecciones presentes.

`Nota`: Es fundamental familiarizarse con los procesos estándar de Windows, como:

- [Session Management Subsystem `smss.exe`](https://en.wikipedia.org/wiki/Session_Manager_Subsystem)
- [Client/Server Runtime Subsystem `csrss.exe`](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem)
- [Winlogon `winlogon.exe`](https://en.wikipedia.org/wiki/Winlogon)
- [Local Security Authority Subsystem Service `LSASS`](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)
- [Service Host `svchost.exe`](https://en.wikipedia.org/wiki/Svchost.exe)

Identificar rápidamente los procesos o servicios estándar nos ayudará a agilizar la enumeración y nos permitirá identificar aquellos que no lo son.

Otros servicios como el de Windows Defender `MsMpEng.exe` son interesantes porque nos permiten identificar protecciones implementadas en el host.

---

## Mostrar todas las variables de entorno

Las variables de entorno explican la configuración del host. `set` imprime todas. Una variable clave es `PATH`: Windows busca ejecutables primero en el directorio de trabajo actual (CWD) y luego en las rutas de `PATH` en orden. Un ejemplo común es colocar Python o Java en el path, lo que permitiría la ejecución de Python o archivos `.JAR`.
Si una carpeta colocada en `PATH` es escribible por el usuario y está antes de `C:\Windows\System32`, puede permitir “DLL Injection” o ejecución de un binario malicioso sin especificar ruta completa.

`set` también da información como `HOMEDRIVE` (a menudo una share de red en empresas). Ficheros colocados en `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup` se ejecutan cuando el usuario inicia sesión en otro equipo (si usan perfil móvil), lo que puede propagar payloads.

---

## Mostrar información detallada de configuración

`systeminfo` muestra si la máquina está parchada recientemente y si es una VM. Si no está parcheada, la escalada puede ser tan simple como ejecutar un exploit conocido. Revisar `HotFix(s)` listados nos da pistas sobre parches instalados. `System Boot Time` también indica si se reinicia con poca frecuencia (posible falta de parches).

### Parches y actualizaciones

Si `systeminfo` no muestra hotfixes, se pueden consultar con WMI/QFE:

```
wmic qfe
```

O con PowerShell:

```
Get-HotFix
```

---

## Programas instalados

WMI puede listar el software instalado. Esto ayuda a encontrar exploits específicos (p. ej. FileZilla, PuTTY). En el texto se sugiere usar LaZagne para comprobar credenciales guardadas en aplicaciones.

```
wmic product get name
```

O con PowerShell:

```
Get-WmiObject -Class Win32_Product | select Name, Version
```

---

## Mostrar procesos en ejecución y conexiones

`netstat` muestra conexiones TCP/UDP y puertos en escucha; útil para detectar servicios locales vulnerables sólo accesibles desde el host.

```
netstat -ano
```

---

## Información de usuarios y grupos

Los usuarios suelen ser el eslabón más débil. Es crucial entender usuarios y grupos en el sistema, miembros que permitan acceso administrador, las políticas de contraseña y usuarios conectados actualmente.

### Usuarios conectados

```
query user
```

### Usuario actual

```
echo %USERNAME%
```

### Privilegios del usuario actual

```
whoami /priv
```

### Grupos del usuario actual

```
whoami /groups
```

### Listar todos los usuarios

```
net user
```

### Listar grupos locales

```
net localgroup
```

### Detalles de un grupo

```
net localgroup administrators
```

### Política de contraseñas

```
net accounts
```

---
