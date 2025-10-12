# Privilegios en Windows
Los **privilegios** en Windows son derechos que se le pueden asignar a una cuenta para realizar operaciones sobre el sistema local: administrar servicios, cargar drivers, apagar el equipo, depurar aplicaciones y más. Los privilegios son distintos de los **derechos de acceso** (access rights) que el sistema utiliza para permitir o denegar acceso a objetos securizables (archivos, claves de registro, etc.).

Las cuentas (usuarios y grupos) y sus privilegios se almacenan en bases de datos del sistema y se entregan al usuario mediante un **token de acceso** (access token) cuando inicia sesión. Una cuenta puede tener privilegios locales en un equipo específico y distintos privilegios en otras máquinas, especialmente si forma parte de un dominio Active Directory.

Cada vez que un usuario intenta realizar una acción privilegiada, el sistema revisa el **token de acceso** del usuario para ver si la cuenta tiene el privilegio requerido y si éste está habilitado. Muchos privilegios están **deshabilitados por defecto**: algunos pueden habilitarse abriendo una consola administrativa (cmd/powershell elevada) y otros deben habilitarse manualmente por scripting.

El objetivo típico de una evaluación (pentest) suele ser obtener acceso administrativo a uno o varios sistemas. Si logramos autenticarnos con una cuenta que ya tiene ciertos privilegios, podemos aprovechar esa funcionalidad integrada para escalar privilegios o usar los privilegios asignados para avanzar hacia el objetivo final.

---

## Proceso de autorización en Windows

Los **principales de seguridad** (security principals) son cualquier entidad que Windows pueda autenticar: cuentas de usuario, cuentas de equipo, procesos que se ejecutan bajo la identidad de una cuenta, o grupos de seguridad. Los security principals son la forma principal de controlar acceso a recursos en hosts Windows.

Cada security principal tiene un identificador único llamado **SID** (Security Identifier). Cuando se crea un principal, se le asigna un SID que permanece con él durante toda su vida.

Cuando un usuario intenta acceder a un objeto securizable (por ejemplo, una carpeta en un recurso compartido), ocurre lo siguiente a alto nivel:

1. El usuario tiene un **token de acceso** que contiene: su User SID, los SIDs de los grupos a los que pertenece, la lista de privilegios y otra información adicional.
2. El objeto (por ejemplo, una carpeta) tiene un **security descriptor** que incluye listas de control de acceso (DACL/SACL) con entradas de control de acceso (ACEs).
3. El sistema compara la información del token del usuario contra las ACEs del descriptor de seguridad hasta encontrar coincidencias.
4. En función de esa comparación, el sistema decide **permitir o denegar** el acceso.

Este proceso de control de acceso ocurre de forma prácticamente instantánea cada vez que un usuario intenta acceder a un recurso. Como pentesters, buscamos formas de **insertarnos o abusar** de este proceso — por ejemplo, aprovechando ACEs mal configuradas, privilegios concedidos o tokens que permitan acciones sensibles.

---

## Grupos y privilegios relevantes en Windows

Windows incluye muchos grupos cuyos miembros obtienen derechos y privilegios potentes. Muchos de estos grupos pueden usarse para escalar privilegios tanto en hosts aislados como en dominios Active Directory. A continuación se listan grupos y su descripción (según el material):

* **Default Administrators**: Grupos superiores (Domain Admins, Enterprise Admins) con permisos "super".
* **Server Operators**: Pueden modificar servicios, acceder a recursos SMB y realizar backups de archivos.
* **Backup Operators**: Pueden iniciar sesión localmente en DCs, crear shadow copies de SAM/NTDS, leer el registro de forma remota y acceder al sistema de archivos vía SMB; deben considerarse equivalentes a Domain Admins en muchas situaciones.
* **Print Operators**: Pueden iniciar sesión en DCs y "engañar" a Windows para cargar un driver malicioso.
* **Hyper-V Administrators**: Si existen DCs virtuales, los administradores de virtualización deben considerarse Domain Admins.
* **Account Operators**: Pueden modificar cuentas y grupos no protegidos en el dominio.
* **Remote Desktop Users**: Por defecto no tienen permisos útiles extra, pero a menudo se les delegan derechos como "Allow logon through Remote Desktop Services" y pueden moverse lateralmente vía RDP.
* **Remote Management Users**: Pueden iniciar sesión en DCs con PSRemoting (a veces añadidos al grupo local de remote management).
* **Group Policy Creator Owners**: Pueden crear GPOs; necesitarían permisos delegados para enlazarlos a contenedores (domain/OU).
* **Schema Admins**: Pueden modificar el esquema de AD y backdoorear objetos o GPOs futuros mediante ACLs por defecto.
* **DNS Admins**: Pueden cargar una DLL en un DC (aunque no siempre reiniciarla); pueden crear registros WPAD como vía de persistencia.

---

## User Rights Assignment (Asignación de derechos de usuario)

Además de la pertenencia a grupos, los usuarios pueden recibir derechos (user rights) configurados por políticas locales o de dominio (GPO). Estos derechos controlan operaciones del sistema como iniciar sesión localmente, acceder desde la red, apagar el equipo, etc. La documentación de Microsoft sobre *User Rights Assignment* describe cada derecho en detalle; aquí se resumen algunos derechos clave mencionados en el material:

| Setting Constant                | Nombre del derecho                           |                                     Asignación estándar | Descripción breve                                                                                                                                                                  |
| ------------------------------- | -------------------------------------------- | ------------------------------------------------------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SeNetworkLogonRight`           | Access this computer from the network        |                     Administrators, Authenticated Users | Define quién puede conectarse al equipo por la red (protocolo SMB, NetBIOS, CIFS, COM+).                                                                                           |
| `SeRemoteInteractiveLogonRight` | Allow log on through Remote Desktop Services |                    Administrators, Remote Desktop Users | Determina quién puede iniciar RDP hacia el equipo (login remoto interactivo).                                                                                                      |
| `SeBackupPrivilege`             | Back up files and directories                |                                          Administrators | Permite saltarse permisos de ficheros/registro para realizar backups.                                                                                                              |
| `SeSecurityPrivilege`           | Manage auditing and security log             |                                          Administrators | Permite ver y limpiar el registro de Seguridad y definir auditorías (SACLs).                                                                                                       |
| `SeTakeOwnershipPrivilege`      | Take ownership of files or other objects     |                                          Administrators | Permite tomar propiedad de cualquier objeto securizable.                                                                                                                           |
| `SeDebugPrivilege`              | Debug programs                               |                                          Administrators | Permite abrir/adjuntar procesos even si no se son dueños (peligroso).                                                                                                              |
| `SeImpersonatePrivilege`        | Impersonate a client after authentication    | Administrators, Local Service, Network Service, Service | Permite que programas impersonen a otro usuario tras autenticación (base para técnicas como Juicy Potato).                                                                         |
| `SeLoadDriverPrivilege`         | Load and unload device drivers               |                                          Administrators | Permite cargar drivers (código en kernel).                                                                                                                                         |
| `SeRestorePrivilege`            | Restore files and directories                |                                          Administrators | Permite restaurar archivos con permisos ignorando ACLs.                                                                                                                            |
| `SeTcbPrivilege`                | Act as part of the operating system          | Administrators, Local Service, Network Service, Service | Permite a un proceso asumir la identidad de cualquier usuario (impersonation) y acceder a recursos a nombre del usuario; se asigna a antivirus y herramientas de backup legítimas. |

---

## Visualizar privilegios: `whoami /priv`

El comando `whoami /priv` devuelve la lista de privilegios asignados al usuario actual y su estado (Enabled/Disabled). Algunos privilegios solo pueden listarse o aprovecharse desde una consola elevada.

Por ejemplo, el material muestra la salida para un administrador local (elevado): la lista completa de privilegios está presente, pero muchos aparecen en estado **Disabled**. Cuando un privilegio aparece como **Disabled**, significa que la cuenta **tiene** ese privilegio asignado pero **no está activo** en el token actual; debe habilitarse para poder usarlo dentro del proceso.

No existe un cmdlet nativo en Windows para "activar" un privilegio en el token; normalmente se recurre a scripts o utilidades que ajusten las capacidades del token (ver ejemplos mencionados en el material).

### Ejemplo (resumen de la salida mostrada)

* `SeImpersonatePrivilege` — *Enabled* en algunos contextos; clave para técnicas de impersonation/relay.
* `SeChangeNotifyPrivilege` — *Enabled* por defecto (bypass traverse checking).
* Muchos privilegios (SeDebugPrivilege, SeBackupPrivilege...) aparecen como *Disabled* hasta que se habiliten en un token elevado.

Un usuario estándar (no elevado) muestra un conjunto mucho más limitado de privilegios — por ejemplo, solo `SeChangeNotifyPrivilege` habilitado.

---

## Derechos de Backup Operators

Los miembros de **Backup Operators** pueden tener derechos como `SeShutdownPrivilege`. Aunque UAC puede restringir ciertos usos, históricamente los Backup Operators pueden leer datos sensibles en controladores de dominio y, por lo tanto, deben considerarse de alto riesgo si están en el dominio.

---

## Detección y monitorización

Para detectar abuso de privilegios, Windows genera eventos (por ejemplo, el evento **4672** — "Special privileges assigned to new logon") cuando ciertos privilegios especiales se asignan a una sesión de logon. Monitorizar estos eventos y revisar privilegios que no deberían asignarse con frecuencia ayuda a prevenir y detectar abusos.

---

## Conclusión / Siguientes pasos

Como atacantes o defensores debemos revisar la membresía de grupos privilegiados y los derechos asignados a cuentas. No es raro encontrar usuarios aparentemente no privilegiados dentro de grupos que les otorgan capacidades potentes. En ejercicios posteriores se analizan implicaciones específicas de los derechos más comunes y técnicas para escalar privilegios cuando se obtiene acceso con cuentas que poseen algunos de estos derechos.

---
