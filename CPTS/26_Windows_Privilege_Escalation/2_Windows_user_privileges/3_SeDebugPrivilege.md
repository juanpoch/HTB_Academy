# SeDebugPrivilege 

El privilegio **SeDebugPrivilege** permite a un usuario o proceso depurar otros procesos, incluyendo los del sistema. Normalmente solo los **administradores** lo tienen asignado, ya que concede la capacidad de leer memoria de procesos protegidos y modificar estructuras críticas del sistema operativo.

Puede asignarse a través de políticas locales o de dominio, bajo:

```
Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Debug programs
```

Este privilegio suele entregarse a **desarrolladores** o personal técnico que necesita depurar aplicaciones o servicios. Sin embargo, representa un **riesgo elevado**, ya que puede usarse para capturar información sensible de la memoria o alterar el comportamiento del sistema.

---

## Contexto en pentesting

Durante un **pentest interno**, SeDebugPrivilege es un objetivo interesante porque permite realizar acciones con privilegios elevados sin necesidad de pertenecer al grupo de administradores.

Por ejemplo:

* Si se obtienen múltiples **hashes NTLMv2** con herramientas como **Responder** o **Inveigh**, conviene priorizar el cracking de cuentas que podrían tener este privilegio (p. ej., cuentas de desarrolladores).
* Un usuario puede **no ser administrador local**, pero tener este derecho asignado, lo cual **no siempre es visible remotamente** (por ejemplo, mediante BloodHound). Por eso es útil comprobarlo manualmente al tener acceso RDP o sesión local.

---

## Enumeración

**Comando:**

```
whoami /priv
```

Permite comprobar si el token del usuario actual incluye `SeDebugPrivilege`.

**Ubicación en políticas locales:**

```
secpol.msc → Local Policies → User Rights Assignment → Debug programs
```

**Por defecto:**

```
Administrators: tienen SeDebugPrivilege
```

---

## Riesgo y abuso

Un usuario con este privilegio puede:

* Acceder a la memoria de procesos del sistema como **LSASS**.
* Volcar credenciales.
* Inyectar o modificar el comportamiento de procesos críticos.

Por ello, conceder SeDebugPrivilege equivale prácticamente a otorgar **control total** sobre el sistema.


---

## Resumen

* **Privilegio:** SeDebugPrivilege
* **Ruta GPO:** Computer Settings → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Debug programs
* **Por defecto:** Administrators
* **Riesgo:** acceso a procesos del sistema y potencial escalada de privilegios
* **Comprobación:** `whoami /priv`
