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

<img width="1288" height="778" alt="image" src="https://github.com/user-attachments/assets/b8a9f0d5-e807-4f2b-bd64-a1d526b7a0f8" />

(Explicación: muestra procesos y servicios asociados a cada PID, útil para detectar qué ejecuta cada svchost.exe.)

[tasklist doc](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist)  


Fijarse en procesos no estándar (por ejemplo, FileZilla Server) para investigar versión o configuraciones. También procesos como `MsMpEng.exe` (Windows Defender) nos indican protecciones presentes.

`Nota`: Es fundamental familiarizarse con los procesos estándar de Windows, como:

- [Session Management Subsystem `smss.exe`](https://en.wikipedia.org/wiki/Session_Manager_Subsystem): Es el proceso del sistema encargado de crear y administrar las sesiones de Windows, inicializando los procesos base que permiten el arranque del sistema y las sesiones de usuario.

| Función                                   | Descripción                                                                                         |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Creación de Session 0**                 | Inicia la sesión del sistema donde se ejecutan los servicios y procesos del kernel.                 |
| **Lanzamiento de procesos críticos**      | Crea `csrss.exe` y `wininit.exe` (para la sesión 0).                                                |
| **Inicialización de sesiones de usuario** | Genera una nueva sesión y ejecuta `csrss.exe` y `winlogon.exe` para cada usuario que inicia sesión. |
| **Configuración del entorno**             | Carga variables de entorno, monta volúmenes y configura el sistema de archivos.                     |
| **Supervisión de procesos críticos**      | Si `csrss.exe` o `winlogon.exe` fallan, provoca un BSOD.                                            |


- [Client/Server Runtime Subsystem `csrss.exe`](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem): Es el proceso del sistema que maneja funciones esenciales del entorno Win32, como la gestión de consolas, la creación de hilos y la comunicación entre procesos de usuario y el sistema.

| Función                             | Descripción                                                               |
| ----------------------------------- | ------------------------------------------------------------------------- |
| **Gestión de consolas**             | Controla la entrada/salida de texto de las ventanas de consola (cmd.exe). |
| **Creación y terminación de hilos** | Colabora con el kernel en la administración de procesos y threads.        |
| **Soporte al entorno Win32**        | Implementa funciones básicas del subsistema Win32 en modo usuario.        |
| **Supervisión del sistema**         | Si falla, provoca el bloqueo completo del sistema (BSOD).                 |
| **Administración de sesiones**      | Existe una instancia por cada sesión activa (sistema o usuario).          |


- [Winlogon `winlogon.exe`](https://en.wikipedia.org/wiki/Winlogon): Es el proceso responsable de gestionar el inicio y cierre de sesión de los usuarios, controlar la pantalla de bloqueo y coordinar la autenticación junto con LSASS.

| Función                                          | Descripción                                                                                                    |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| **Inicio de sesión interactivo**                 | Recibe las credenciales del usuario (a través de la interfaz de logon) y las envía a LSASS para autenticación. |
| **Bloqueo y desbloqueo del sistema**             | Controla la pantalla de bloqueo y el ingreso de Ctrl+Alt+Del.                                                  |
| **Carga del perfil de usuario**                  | Inicia la sesión del usuario tras la autenticación, cargando su entorno y variables.                           |
| **Ejecución de `userinit.exe` y `explorer.exe`** | Lanza los procesos que construyen el entorno de escritorio.                                                    |
| **Supervisión de la sesión**                     | Monitorea el estado del usuario; si falla, el sistema no puede iniciar sesión.                                 |
| **Cierre de sesión y apagado**                   | Coordina el cierre seguro de la sesión del usuario o el sistema.                                               |

- [Local Security Authority Subsystem Service `LSASS`](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service): Es el proceso encargado de aplicar las políticas de seguridad del sistema operativo, autenticar usuarios y emitir tokens de acceso para controlar qué puede hacer cada proceso o cuenta.

| Función                                  | Descripción                                                                                         |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Autenticación de usuarios**            | Valida las credenciales locales o de dominio (contraseña, hash, Kerberos, NTLM).                    |
| **Generación de tokens de acceso**       | Crea los tokens que definen los permisos y privilegios de cada sesión o proceso.                    |
| **Aplicación de políticas de seguridad** | Enforcea reglas de contraseñas, bloqueo de cuentas, privilegios y auditoría.                        |
| **Comunicación con SAM y AD**            | Interactúa con la base de cuentas locales (SAM) o con Active Directory en equipos unidos a dominio. |
| **Gestión de auditorías**                | Registra eventos de seguridad como inicios de sesión, errores o accesos no autorizados.             |
| **Protección del sistema**               | Si se detiene, el sistema entra en error crítico (BSOD).                                            |

- [Service Host `svchost.exe`](https://en.wikipedia.org/wiki/Svchost.exe): Es un proceso contenedor que ejecuta uno o varios servicios de Windows, agrupándolos para optimizar el uso de recursos y facilitar su administración.

| Función                              | Descripción                                                                                                      |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| **Alojamiento de servicios**         | Carga y ejecuta servicios del sistema definidos en DLLs (no ejecutables directos).                               |
| **Agrupación por funciones**         | Ejecuta múltiples servicios relacionados dentro de una misma instancia para ahorrar memoria.                     |
| **Separación por seguridad**         | Crea instancias distintas (svchost) para servicios de diferente nivel de privilegio o contexto.                  |
| **Gestión mediante SCM**             | Recibe instrucciones del *Service Control Manager* (`services.exe`) para iniciar, detener o reiniciar servicios. |
| **Ejecución en distintos contextos** | Puede correr bajo cuentas como `LocalSystem`, `NetworkService` o `LocalService`, según el servicio.              |
| **Supervisión de estabilidad**       | Si un servicio falla, puede reiniciarse sin afectar a todo el sistema.                                           |

- [Service Control Manager `services.exe`](https://es.wikipedia.org/wiki/Service_Control_Manager): Es el proceso del sistema responsable de administrar todos los servicios de Windows, incluyendo su inicio, detención, configuración y supervisión.

| Función                           | Descripción                                                                                                     |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Inicio de servicios**           | Carga y ejecuta todos los servicios configurados para iniciarse con el sistema.                                 |
| **Gestión de `svchost.exe`**      | Lanza y controla los procesos `svchost.exe` que alojan servicios basados en DLL.                                |
| **Monitoreo de estado**           | Supervisa los servicios en ejecución y reinicia los que fallen, según las políticas configuradas.               |
| **Comunicación con aplicaciones** | Permite a otros programas iniciar, detener o consultar servicios mediante la API del *Service Control Manager*. |
| **Control de dependencias**       | Asegura que los servicios se inicien o detengan en el orden correcto según sus dependencias.                    |
| **Interfaz con el usuario**       | Se comunica con el panel *services.msc* y con `net start` / `net stop` para recibir órdenes.                    |

- Windows Initialization Process `wininit.exe`: Es un proceso del sistema que se ejecuta durante el arranque de Windows y se encarga de inicializar los servicios esenciales en la sesión 0, incluyendo `services.exe`, `lsass.exe` y `lsaiso.exe`.

| Función                            | Descripción                                                                                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Creación de procesos críticos**  | Inicia `services.exe` (administrador de servicios), `lsass.exe` (subsistema de seguridad) y `lsaiso.exe` (LSA aislado, si está habilitado). |
| **Inicialización de la sesión 0**  | Configura la sesión del sistema donde se ejecutan los servicios y controladores.                                                            |
| **Manejo del registro de eventos** | Inicia el servicio de *Windows Event Log* (`eventlog.dll`) para registrar eventos del sistema.                                              |
| **Comunicación con SMSS**          | Trabaja junto al *Session Manager Subsystem* (`smss.exe`) para completar la secuencia de arranque.                                          |
| **Supervisión de procesos hijos**  | Si alguno de los procesos críticos que crea falla, el sistema genera un *BSOD*.                                                             |
| **Ejecutado solo una vez**         | Se lanza una sola instancia durante el arranque y permanece activa en segundo plano.                                                        |


Identificar rápidamente los procesos o servicios estándar nos ayudará a agilizar la enumeración y nos permitirá identificar aquellos que no lo son.

Otros servicios como el de Windows Defender `MsMpEng.exe` son interesantes porque nos permiten identificar protecciones implementadas en el host.

---

## Mostrar todas las variables de entorno

Las variables de entorno explican la configuración del host.
`set` imprime todas las variables de entorno. Una variable clave es `PATH`: Windows busca ejecutables primero en el directorio de trabajo actual y luego en las rutas de `PATH` en orden de izquierda a derecha, por lo que es más peligrosa una ruta custom a la izquierda del `path`. Un ejemplo común es colocar Python o Java en el path, lo que permitiría la ejecución de Python o archivos `.JAR`.
Si una carpeta colocada en `PATH` es escribible por el usuario y está antes de `C:\Windows\System32`, puede permitir “DLL Injection” contra otras aplicaciones.

`Nota`: Una `DLL` es una biblioteca de código usada por los programas.
En una `DLL Injection`, se fuerza a un proceso legítimo a cargar una `DLL` maliciosa.
La relación con el PATH está en que el orden de búsqueda de `DLLs` puede ser manipulado para que Windows cargue la versión maliciosa primero, lo que se conoce como `DLL Hijacking`.

`set` también da información como `HOMEDRIVE` (a menudo una carpeta compartida de red en empresas). Acceder al recurso compartido puede revelar otros directorios accesibles con información potencialmente sensible.

Ficheros colocados en `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup` se ejecutan cuando el usuario inicia sesión en otro equipo (si usan perfil móvil), lo que puede propagar payloads.

[Perfil móvil doc](https://learn.microsoft.com/es-es/windows-server/storage/folder-redirection/folder-redirection-rup-overview)

El perfil móvil es un tipo de perfil de usuario en Windows que se almacena en un servidor y se descarga localmente al iniciar sesión, permitiendo que el usuario mantenga su mismo entorno (escritorio, documentos, configuraciones) desde cualquier equipo del dominio.

| Motivo                          | Descripción                                                                                                                      |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Sincronización automática**   | Cualquier archivo malicioso en el perfil (por ejemplo, en *AppData* o *Startup*) se replica a otros equipos al iniciar sesión.   |
| **Uso de recursos compartidos** | El perfil se guarda en un recurso SMB del servidor (`\\servidor\profiles\usuario`), lo que puede servir como punto de infección. |
| **Permisos amplios**            | Los usuarios suelen tener permisos de escritura en su carpeta de perfil, facilitando la persistencia del payload.                |
| **Ejecución transversal**       | Si el usuario inicia sesión en múltiples hosts, el malware se propaga automáticamente a todos ellos.                             |

`Conclusión`: Un perfil móvil comprometido permite que un payload se propague entre varios equipos del dominio de forma silenciosa y legítima, aprovechando la sincronización automática del perfil del usuario.

---

## Mostrar información detallada de configuración

`systeminfo` muestra si la máquina está parchada recientemente y si es una VM. Si no está parcheada, la escalada puede ser tan simple como ejecutar un exploit conocido. Revisar `HotFix(s)` listados nos da pistas sobre parches instalados, utilizar el número `Knowledge Base` para buscarlo en  [Revisiones](https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix). `System Boot Time` también indica si se reinicia con poca frecuencia (posible falta de parches).

<img width="1434" height="855" alt="image" src="https://github.com/user-attachments/assets/f37b7ab1-5faf-452b-8642-8888f6cf0b7b" />

<img width="1619" height="908" alt="image" src="https://github.com/user-attachments/assets/7547da93-ef0c-4bc5-b8b4-778224fb2806" />

Nosotros tenemos:
```
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
...
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB5001078
                           [03]: KB4103723
```

Si buscamos `KB3199986` en el catálogo encontramos:
<img width="1891" height="475" alt="image" src="https://github.com/user-attachments/assets/8bff0545-005b-4a4c-877c-d33c19bcebd5" />

Descubrimos que el último parche instalado corresponde al año 2021, por lo que tendríamos varios años sin parchear.

A su vez, si buscamos en el catálogo por `Windows Server 2016 cumulative update` podremos identificar todos los KB acumulativos que no están instalados:
<img width="1876" height="962" alt="image" src="https://github.com/user-attachments/assets/5f2c19df-22a1-4717-9192-b643bcaea988" />


`Nota`: También puede ser útil revisar los datos de red, por si se descubren conexiones a otras redes.
### Parches y actualizaciones

Si `systeminfo` no muestra hotfixes, se pueden consultar con [WMI](https://learn.microsoft.com/es-es/windows/win32/wmisdk/wmi-start-page)/[QFE](https://learn.microsoft.com/es-es/windows/win32/cimwin32prov/win32-quickfixengineering):

```
wmic qfe
```
<img width="1645" height="255" alt="image" src="https://github.com/user-attachments/assets/2fbfe1a0-cb5f-476f-8f0b-b327d393a9f9" />

`Nota`: `WMI`: Base de datos + interfaz + comandos que dejan consultar o controlar casi cualquier cosa del sistema

`Nota`: `QFE`: registro interno del sistema de cada parche instalado.

O con PowerShell usando el cmdlet [Get-HotFix](https://learn.microsoft.com/es-es/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.5&viewFallbackFrom=powershell-7.1):


```
Get-HotFix
```
<img width="1419" height="319" alt="image" src="https://github.com/user-attachments/assets/42d21ec7-c776-45bf-b539-c9e146e031d4" />


`Nota`: `ft` es formato tabla y `-AutoSize` ajusta automáticamente el ancho de las columnas según el contenido.

---

## Programas instalados

WMI puede listar el software instalado. Esto ayuda a encontrar exploits específicos (p. ej. FileZilla, PuTTY). Se sugiere usar `LaZagne` para comprobar credenciales guardadas en aplicaciones.

```
wmic product get name
```

<img width="1395" height="386" alt="image" src="https://github.com/user-attachments/assets/bff3461b-18f4-4dfd-8d90-8e09a798e8e1" />

O con PowerShell utilizando el cmdlet [Get-WmiObject](https://learn.microsoft.com/es-es/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1):

```
Get-WmiObject -Class Win32_Product | select Name, Version
```
<img width="1387" height="792" alt="image" src="https://github.com/user-attachments/assets/87a52827-aa4c-4c72-8be9-6f0bcbfdee70" />


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
