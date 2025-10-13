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

* Supongamos además que hemos obtenido un conjunto de credenciales dentro de un archivo llamado:
  `logins.sql`
  encontrado en un recurso compartido de red (file share).

* Dicho archivo fue descubierto utilizando una herramienta como:
  `Snaffler`
  que busca archivos y datos sensibles en redes Windows, como contraseñas, llaves o configuraciones con permisos inseguros.

---


Conectando con MSSQLClient.py

**Contexto**

Con las credenciales `sql_dev:Str0ng_P@ssw0rd!`, primero nos conectamos a la instancia de SQL Server y verificamos los privilegios asociados a dicha cuenta. Esta fase nos permite determinar el nivel de acceso disponible dentro del servicio SQL, lo cual es crucial antes de intentar cualquier tipo de explotación o escalada.

Para realizar esta conexión, utilizamos la herramienta **`mssqlclient.py`** incluida en el paquete **Impacket**, una colección de utilidades para interactuar con diversos protocolos de red y servicios de Windows (como SMB, RDP, MSSQL, LDAP, etc.).

---

**Ejemplo de conexión**

```
mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```

Al ejecutar este comando, el cliente intenta autenticarse contra el servicio MSSQL en la dirección IP del servidor utilizando autenticación de Windows (`-windows-auth`).

Una vez ingresada la contraseña, el cliente establece la conexión TLS y muestra información relevante del entorno:

* Cambio de base de datos al contexto `master`.
* Cambio de idioma a `us_english`.
* Ajuste del tamaño de paquete (`PACKETSIZE`).
* Confirmación de conexión exitosa al servidor (`Microsoft SQL Server`).

El mensaje final:

```
[!] Press help for extra shell commands
SQL>
```

indica que la conexión ha sido establecida correctamente y que ahora contamos con un **prompt interactivo de SQL**, desde el cual es posible ejecutar consultas y comandos.

---

**Objetivo de esta etapa**

1. Validar que las credenciales proporcionadas son válidas.
2. Confirmar el tipo de autenticación utilizada (en este caso, autenticación integrada de Windows).
3. Verificar si el usuario tiene permisos elevados dentro de SQL Server (por ejemplo, acceso a `xp_cmdshell` o pertenencia al rol `sysadmin`).
4. Preparar el entorno para posibles técnicas de escalada de privilegios aprovechando configuraciones o permisos indebidos.

---

**Herramientas clave**

| Herramienta      | Descripción                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| `mssqlclient.py` | Cliente de Impacket que permite autenticarse y ejecutar comandos en servidores MSSQL.                              |
| `Impacket`       | Framework en Python para interactuar con servicios y protocolos de red de Windows.                                 |
| `SQL Server`     | Servicio de base de datos que puede ser explotado para ejecutar código o moverse lateralmente en entornos Windows. |

---

**Importancia práctica**

Este paso inicial es fundamental en una auditoría o laboratorio de escalada en Windows, ya que una conexión válida a SQL Server puede abrir múltiples caminos de explotación: desde la ejecución de comandos en el sistema operativo con `xp_cmdshell`, hasta la extracción de credenciales o la suplantación de tokens mediante privilegios como `SeImpersonatePrivilege`.

