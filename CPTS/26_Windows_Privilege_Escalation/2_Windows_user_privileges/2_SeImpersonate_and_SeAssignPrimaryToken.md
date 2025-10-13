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
  `mssqlserver`

* Imaginemos que logramos ejecutar comandos como este usuario utilizando:
  `xp_cmdshell`
  Este procedimiento almacenado de SQL permite ejecutar comandos del sistema desde SQL Server (por ejemplo, `whoami`, `dir`, etc.), lo cual representa un punto de ejecución remota de comandos (RCE).

* Supongamos además que hemos obtenido un conjunto de credenciales dentro de un archivo llamado:
  logins.sql
  encontrado en un recurso compartido de red (file share).

* Dicho archivo fue descubierto utilizando una herramienta como:
  Snaffler
  que busca archivos y datos sensibles en redes Windows, como contraseñas, llaves o configuraciones con permisos inseguros.

Conclusión

Este escenario demuestra cómo un atacante con acceso a una cuenta de servicio con privilegio SeImpersonatePrivilege puede:

1. Ejecutar comandos en el servidor SQL.
2. Identificar credenciales almacenadas en recursos de red.
3. Potencialmente elevar privilegios a SYSTEM utilizando herramientas como JuicyPotato, aprovechando la suplantación de tokens (token impersonation).

Conceptos clave

SeImpersonatePrivilege → Permite ejecutar procesos bajo el contexto de otro usuario autenticado.
xp_cmdshell → Procedimiento de SQL Server que ejecuta comandos del sistema operativo.
mssqlserver → Cuenta por defecto bajo la cual se ejecuta el servicio de SQL Server.
JuicyPotato → Explotación de DCOM/SeImpersonatePrivilege para elevar privilegios a SYSTEM.
Snaffler → Herramienta para localizar archivos sensibles en redes Windows.

Lección práctica

Cuando un servicio tiene el privilegio SeImpersonatePrivilege, no es necesario que sea administrador local para escalar privilegios.
La explotación mediante JuicyPotato o similares aprovecha la delegación insegura de tokens para ejecutar código con privilegios de SYSTEM.

Flujo simplificado:

Service Account (con SeImpersonatePrivilege)
↓
Explotación (JuicyPotato)
↓
NT AUTHORITY\SYSTEM




