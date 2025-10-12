# Privilegios en Windows
Los [**privilegios**](https://learn.microsoft.com/es-es/windows/win32/secauthz/privileges) en Windows son derechos que se le pueden asignar a una cuenta para realizar operaciones sobre el sistema local: administrar servicios, cargar drivers, apagar el equipo, depurar aplicaciones y más. Los privilegios son distintos de los **derechos de acceso** (access rights) que el sistema utiliza para permitir o denegar acceso a objetos securizables (archivos, claves de registro, etc.).

Las cuentas (usuarios y grupos) y sus privilegios se almacenan en bases de datos del sistema y se entregan al usuario mediante un **token de acceso** (access token) cuando inicia sesión. Una cuenta puede tener privilegios locales en un equipo específico y distintos privilegios en otras máquinas, especialmente si forma parte de un dominio Active Directory.

Cada vez que un usuario intenta realizar una acción privilegiada, el sistema revisa el **token de acceso** del usuario para ver si la cuenta tiene el privilegio requerido y si éste está habilitado. Muchos privilegios están **deshabilitados por defecto**: algunos pueden habilitarse abriendo una consola administrativa (cmd/powershell elevada) y otros deben habilitarse manualmente por scripting.

El objetivo típico de una evaluación (pentest) suele ser obtener acceso administrativo a uno o varios sistemas. Si logramos autenticarnos con una cuenta que ya tiene ciertos privilegios, podemos aprovechar esa funcionalidad integrada para escalar privilegios o usar los privilegios asignados para avanzar hacia el objetivo final.

---

## Proceso de autorización en Windows

Los **principales de seguridad** (security principals) son cualquier entidad que Windows pueda autenticar: cuentas de usuario, cuentas de equipo, procesos que se ejecutan bajo la identidad de una cuenta, o grupos de seguridad. Los security principals son la forma principal de controlar acceso a recursos en hosts Windows.

Cada security principal tiene un identificador único llamado [**SID**](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-identifiers) (Security Identifier). Cuando se crea un principal, se le asigna un SID que permanece con él durante toda su vida.

El sistema operativo genera un `SID` que identifica una cuenta o grupo determinado en el momento en que se crea la cuenta o el grupo. Para una cuenta o grupo local, la `autoridad de seguridad local (LSA)` del equipo genera el `SID`. El SID se almacena con otra información de cuenta en un área segura del registro.



[Subsistema de seguridad (concepto global)]
   ├─> [Proceso: lsass.exe (Local Security Authority Subsystem Service) — corre como SYSTEM]
   │       ├─> [LSA (Local Security Authority) — lógica central dentro de lsass.exe / lsasrv.dll]
   │       │       ├─> Crea Access Tokens (User SID, Group SIDs, Privileges)
   │       │       ├─> Carga Authentication Packages (NTLM → msv1_0.dll, Kerberos → kerberos.dll, etc.)
   │       │       ├─> Gestiona LSA Secrets (HKLM\SECURITY\Policy\Secrets)
   │       │       ├─> Consulta SAM (archivo hive) y/o Domain Controllers (DCs) vía RPC
   │       │       ├─> Gestiona políticas locales de seguridad (audit, rights, restrictions)
   │       │       └─> Interfaz RPC LSA para otros procesos (Winlogon, services, etc.)
   │       │
   │       ├─> [SAM Server — samsrv.dll]
   │       │       ├─> Administra cuentas locales (usuarios, grupos)
   │       │       ├─> Interfaz RPC para lectura/escritura de credenciales locales
   │       │       └─> Interactúa con la hive HKLM\SAM
   │       │
   │       ├─> [Netlogon — netlogon.dll (parte en lsass.exe)]
   │       │       ├─> Autenticación con DCs (secure channel)
   │       │       ├─> Validación de cuentas de dominio
   │       │       └─> Administración de trusts y replicación segura
   │       │
   │       ├─> [Authentication Packages cargados por LSA]
   │       │       ├─> msv1_0.dll → NTLM
   │       │       ├─> kerberos.dll → Kerberos
   │       │       ├─> wdigest.dll → Digest Authentication (legacy)
   │       │       ├─> tspkg.dll → Terminal Services
   │       │       └─> livessp.dll / cloudap.dll → SSO / Azure AD
   │       │
   │       ├─> [SSPs — Security Support Providers / SSPI]
   │       │       ├─> schannel.dll → TLS/SSL
   │       │       ├─> credssp.dll → RDP / CredSSP
   │       │       ├─> negoexts.dll → Negotiate (Kerberos/NTLM fallback)
   │       │       └─> secur32.dll → Interfaz SSPI para aplicaciones
   │       │
   │       ├─> [Policy Engine — policyeng.dll]
   │       │       ├─> Aplica políticas locales y de dominio (rights, audit)
   │       │       └─> Integra configuraciones de secpol.msc / gpedit.msc
   │       │
   │       └─> [Protected Process Light (PPL)]
   │               ├─> Aísla lsass.exe contra lectura de memoria por procesos no protegidos
   │               └─> Gestionado por el kernel driver lsass.sys (Windows 8+)
   │
   ├─> [Winlogon / Logon Subsystem]
   │       ├─> Interactúa con LSA vía RPC para iniciar sesión
   │       ├─> Carga Credential Providers (UI / GINA / credenciales)
   │       ├─> Crea la sesión del usuario (winlogon.exe + userinit.exe)
   │       └─> Usa el token generado por LSA
   │
   ├─> [Otros componentes en espacio de usuario relacionados con seguridad]
   │       ├─> Security Accounts Manager (herramientas administrativas)
   │       ├─> secpol.msc / gpedit.msc (interfaz de políticas)
   │       ├─> services.exe / svchost.exe (pueden usar SSPI)
   │       └─> Aplicaciones que consumen SSPI (Outlook, IIS, etc.)
   │
   └─> [En kernel — parte del subsistema de seguridad]
           ├─> [Security Reference Monitor (SRM)]
           │       ├─> Evalúa Access Tokens vs DACL/SACL
           │       ├─> Aplica las decisiones de acceso (permitir/denegar)
           │       ├─> Implementa auditoría de seguridad
           │       └─> Llamado desde Executive Object Manager, I/O Manager, etc.
           │
           └─> [Otros componentes kernel relacionados]
                   ├─> SeMgr / SeAccessCheck / SeToken APIs
                   ├─> Object Manager (OBJ) — integra seguridad a objetos del sistema
                   ├─> Reference Monitor Hooks
                   └─> Kernel-mode authentication drivers (krnlsec, lsass.sys)  
                   


El Registro de Windows es una base de datos jerárquica que almacena la configuración y parámetros del sistema operativo, hardware, aplicaciones y cuentas de usuario, utilizada por Windows y sus servicios para cargar y mantener su estado y funcionamiento.

[Registro]
├─ HKLM\SAM\SAM\Domains\Account\Users\{RID}   → Cuentas y grupos locales (SID + hashes)
│
├─ HKLM\SAM\SAM\Domains\Account                → Domain SID local (base para todos los locales)
│
├─ HKLM\SECURITY\Cache                         → Caché de cuentas de dominio (SIDs + credenciales)
│
└─ Hardcoded en el sistema                     → Well-known SIDs (SYSTEM, Administrators, Everyone, etc.)  






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
