# Situational Awareness — Windows Privilege Escalation

* Tomar una **foto del entorno**: red, interfaces, rutas, controles defensivos, dominio/AD, usuarios activos, políticas de ejecución.
* Objetivo: pasar de actuar **reactivamente** a **proactivamente** planificando la ruta de PrivEsc y movimiento lateral.

**Preguntas clave**

* ¿El host es **dual‑homed**? ¿A qué subredes llega?
* ¿Qué **controles** me frenan (AV/EDR, AppLocker, WDAC)?
* ¿Qué **herramientas** puedo usar sin disparar alertas? ¿Necesito técnicas manuales?
* ¿Qué **rutas** existen hacia DCs, servidores de BD, shares sensibles?

---

## Enumeración de Red 

> Ejecutar y guardar salida en `loot/network_*.txt`.

### Interfaces, IPs, DNS

```cmd
ipconfig /all
```

**Interpretación:** detectar IPs, gateways, DNS, sufijos de búsqueda, si está unido a dominio y **múltiples NICs** (dual‑homed).

### 2.2 ARP cache (vecinos recientes)

```cmd
arp -a
```

**Interpretación:** hosts recientemente comunicados → candidatos a RDP/WinRM/SMB para lateral movement.

### 2.3 Tabla de rutas (alcance real)

```cmd
route print
```

**Interpretación:** rutas por interfaz, métricas, gateways. Identificar subredes internas accesibles (p. ej. `192.168.20.0/24` además de `10.129.0.0/16`).

### 2.4 Dominio / AD (si aplica)

```powershell
whoami /fqdn
nltest /dsgetdc:htb
ipconfig /displaydns | findstr /i "_ldap _kerberos"
```

**Interpretación:** DCs, servicios Kerberos/LDAP, nombre de dominio.

### 2.5 Resolución y reachability

```cmd
nslookup dc01.htb
ping -n 1 10.129.0.1
tracert 10.129.0.1
```

**Interpretación:** latencia, salto de gateways, visibilidad entre VLANs.

> **Tip:** si ves dos adaptadores activos (por ejemplo `10.129.43.8` y `192.168.20.56`) y rutas por ambos, estás ante un **pivot** natural.

---

## Ejemplo guiado de lectura (fragmentos provistos)

**Interfaces** (salida de `ipconfig /all`):

* `Ethernet0` → `10.129.43.8/16`, DNS `1.1.1.1` y `8.8.8.8`, gateway `10.129.0.1`.
* `Ethernet1` → `192.168.20.56/24`, gateway `192.168.20.1`, DNS `8.8.8.8`.
* **Conclusión**: **dual‑homed** → posible salto hacia `192.168.20.0/24` desde un box en `10.129.0.0/16`.

**ARP** (salida de `arp -a`):

* Varios vecinos en `10.129.43.x`; usar como objetivos de RDP/SMB. Broadcasts y multicasts listados son normales.

**Rutas** (salida de `route print`):

* Ruta por defecto por `10.129.0.1` (métrica 25) y otra por `192.168.20.1` (métrica 271). El tráfico saldrá preferente por **10.129.0.1**.
* Rutas on‑link para `192.168.20.0/24` → podemos alcanzar esa red directamente.

---

## Enumeración de Protecciones (AV/EDR, AppLocker)

### Estado de Windows Defender

```powershell
Get-MpComputerStatus | fl AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureVersion
```

**Lectura rápida:** si `RealTimeProtectionEnabled`/`OnAccessProtectionEnabled` están `True`, espera bloqueos/alertas. Si están `False`, el lab puede estar relajado.

### AppLocker 

```powershell
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
```

* Revisa reglas por **Publisher/Path/Hash** en `Exe`, `Msi`, `Script`, `PackagedApps`.

**Probar una ruta concreta:**

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```

* Devuelve `PolicyDecision: Allowed/Denied`. Útil para decidir **dónde** ubicar binarios/scripts (p. ej. `%WINDIR%` y `%PROGRAMFILES%` suelen estar permitidos por default rules para Everyone).

> **Nota:** si ves denial para `cmd.exe` / `powershell.exe`, prepara bypass (LOLBAS, msbuild, installutil, wmic, regsvr32, fodhelper, etc.) o rutas permitidas.

### Otros controles a considerar

* **WDAC / Device Guard**: políticas de firma; revisar `Get-CimInstance -ClassName Win32_DeviceGuard`.
* **Applocker logs**: `Event Viewer → Applications and Services Logs → Microsoft → Windows → AppLocker`.
* **EDR**: procesos bloqueados, *command‑line telemetry*; variar binarios y técnicas manuales.

---

## Decisión táctica (árbol rápido)

1. **¿Dual‑homed?** Sí → mapear subred secundaria (port scan desde el host, SMB shares, DCs) y considerar pivot.
2. **¿AppLocker estricto?** Sí → usar LOLBAS/paths permitidos o compilar binarios firmados.
3. **¿Defender/EDR activo?** Sí → técnicas manuales primero (enumeración nativa). Evitar herramientas ruidosas (winPEAS/LaZagne) hasta ajustar.
4. **¿En dominio?** Sí → enumerar DCs, SPNs, sesiones administrativas, `Invoke-ShareFinder`/`net view`.

---

## Playbook: comandos mínimos a correr (copiar/pegar)

```powershell
# RED
ipconfig /all
arp -a
route print

# DOMINIO
whoami /fqdn
nltest /dsgetdc:$(($env:USERDNSDOMAIN))

# DEFENSAS
Get-MpComputerStatus | fl AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```

---



## Siguientes pasos

* Con la foto de red y defensas, seleccionar **técnicas y herramientas** para la enumeración local (servicios, ACLs, tareas) y/o **rutas de movimiento lateral**.
* Preparar **bypasses** si AppLocker/EDR bloquea binarios base.

---
