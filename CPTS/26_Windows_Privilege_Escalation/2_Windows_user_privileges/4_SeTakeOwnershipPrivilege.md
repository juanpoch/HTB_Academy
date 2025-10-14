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

# Riesgos y uso de **SeTakeOwnershipPrivilege**

Con este privilegio, un usuario puede **tomar la propiedad** de cualquier archivo u objeto y realizar cambios que impliquen acceso a datos sensibles, ejecución remota de código o incluso producir denegación de servicio sobre recursos críticos.

## Escenario de abuso

Si detectamos un usuario que posee este privilegio —o si logramos asignárselo mediante un ataque (por ejemplo abuso de GPO con herramientas como [`SharpGPOAbuse`)](https://github.com/FSecureLABS/SharpGPOAbuse)— podemos aprovecharlo para:

* **Tomar control de un recurso compartido** y cambiar permisos/propietario para acceder a ficheros protegidos.
* **Acceder a ficheros sensibles** (documentos con contraseñas, claves SSH, backups) cambiando el owner y luego modificando la ACL para concedernos lectura/escritura.
* **Provocar DoS** sobre servicios que dependen de ficheros concretos (por ejemplo bloquear o sustituir ficheros de configuración críticos).
* **Facilitar RCE** en casos donde la manipulación de un ejecutable/servicio permita ejecutar código con mayor privilegio.


