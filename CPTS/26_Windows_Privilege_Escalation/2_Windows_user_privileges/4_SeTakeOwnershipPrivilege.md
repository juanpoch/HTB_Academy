# SeTakeOwnershipPrivilege

**SeTakeOwnershipPrivilege** concede a un usuario la capacidad de **tomar posesión** de cualquier "objeto asegurnable" (*securable object*), lo que incluye objetos de Active Directory, archivos/carpetas NTFS, impresoras, claves de registro, servicios y procesos. Este privilegio asigna derechos de **WRITE_OWNER** sobre un objeto, lo que significa que el usuario puede **cambiar el propietario** dentro del descriptor de seguridad del objeto.

Los administradores reciben este privilegio por defecto. Aunque es poco frecuente encontrar una cuenta de usuario estándar con este privilegio, sí es posible toparse con **cuentas de servicio** que lo tengan asignado —por ejemplo, cuentas encargadas de ejecutar trabajos de copia de seguridad y snapshots VSS—. A estas cuentas normalmente también se les asignan otros privilegios relacionados, como **SeBackupPrivilege**, **SeRestorePrivilege** y **SeSecurityPrivilege**, para controlar sus capacidades de forma granular sin darles derechos totales de administrador local.

Estas capacidades por sí solas **pueden** facilitar una escalada de privilegios. Sin embargo, en algunos escenarios necesitaremos **tomar la propiedad** de ficheros específicos porque otros métodos están bloqueados o no funcionan como se espera. El abuso de este privilegio es un caso algo extremo (edge case), pero vale la pena comprenderlo en profundidad, especialmente en entornos Active Directory donde podríamos asignar este derecho a un usuario controlado y aprovecharlo para leer un archivo sensible en un recurso compartido.


---


