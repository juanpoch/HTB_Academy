# NFS (Network File System) – Guía Completa de Enumeración y Explotación

---

# 1. Introducción a NFS

**Network File System (NFS)** es un sistema de archivos en red desarrollado por Sun Microsystems cuyo objetivo es permitir el acceso a sistemas de archivos remotos como si fueran locales.

A diferencia de SMB (usado principalmente en entornos Windows), NFS se utiliza principalmente entre sistemas **Linux y Unix**.

⚠️ Un cliente NFS no puede comunicarse directamente con un servidor SMB.

[NFS](https://en.wikipedia.org/wiki/Network_File_System) es un estándar de Internet que define los procedimientos de un sistema de archivos distribuido.

---

# 2. Versiones de NFS

| Versión                | Características                                                                                                |
| ---------------------- | -------------------------------------------------------------------------------------------------------------- |
| **NFSv2**              | Versión antigua, soportada por muchos sistemas. Operaba completamente sobre UDP.                               |
| **NFSv3**              | Soporta tamaños de archivo variables y mejor reporte de errores. No totalmente compatible con NFSv2.           |
| **NFSv4**              | Incluye Kerberos, funciona a través de firewalls, usa puerto 2049, soporta ACLs, es stateful, mayor seguridad. |
| **NFSv4.1 ([RFC 8881](https://datatracker.ietf.org/doc/html/rfc8881))** | Soporta despliegues en clúster, acceso paralelo (pNFS), multipathing (session trunking).                       |

### Diferencia crítica entre v3 y v4

* **NFSv3** autentica el equipo cliente.
* **NFSv4** requiere autenticación del usuario (similar a SMB moderno).

Una ventaja importante de NFSv4 es que utiliza únicamente el puerto:

```
2049/TCP o UDP
```

Lo que facilita su paso a través de firewalls.

---

# 3. Arquitectura Interna

NFS se basa en:

* [**ONC-RPC (Open Network Computing Remote Procedure Call)**](https://en.wikipedia.org/wiki/Sun_RPC)
* También conocido como SUN-RPC
* Usa representación de datos independiente del sistema ([XDR](https://en.wikipedia.org/wiki/External_Data_Representation))

Puertos importantes:

| Puerto | Servicio             |
| ------ | -------------------- |
| 111    | rpcbind / portmapper |
| 2049   | NFS                  |

⚠️ NFS por sí mismo no implementa autenticación ni autorización.

La autenticación depende de RPC.
La autorización depende de la información del sistema de archivos.

Generalmente se usa autenticación basada en:

* UID
* GID
* Membresías de grupo

Problema importante:

El cliente y el servidor pueden tener mapeos diferentes de UID/GID. El servidor no realiza validaciones adicionales.

Por eso NFS solo debería utilizarse en redes confiables.

---

# 4. Configuración por Defecto

El archivo principal de configuración es:

```
/etc/exports
```

Contenido por defecto:

```bash
CyberWolfSec@htb[/htb]$ cat /etc/exports

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```

Formato general:

```
/directorio  host(opciones)
```

---

# 5. Opciones Comunes

| Opción           | Descripción                         |
| ---------------- | ----------------------------------- |
| rw               | Permite lectura y escritura         |
| ro               | Solo lectura                        |
| sync             | Transferencia síncrona              |
| async            | Transferencia asíncrona             |
| secure           | Solo puertos <1024                  |
| insecure         | Permite puertos >1024               |
| no_subtree_check | Desactiva chequeo de subdirectorios |
| root_squash      | Mapea root a usuario anónimo        |

---

# 6. Creación de un Export

Ejemplo práctico:

```bash
root@nfs:~# echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
root@nfs:~# systemctl restart nfs-kernel-server
root@nfs:~# exportfs

/mnt/nfs      	10.129.14.0/24
```

Se comparte `/mnt/nfs` a toda la red `10.129.14.0/24`.

---

# 7. Configuraciones Peligrosas

| Opción         | Riesgo                          |
| -------------- | ------------------------------- |
| rw             | Permite modificar archivos      |
| insecure       | Permite uso de puertos altos    |
| nohide         | Expone sistemas montados debajo |
| no_root_squash | Root remoto mantiene UID 0      |

⚠️ `no_root_squash` es extremadamente peligroso.

Permite que root remoto cree archivos con UID 0 reales.

---

# 8. Footprinting del Servicio

Puertos clave:

* 111 (rpcbind)
* 2049 (nfs)

---

## Escaneo básico con Nmap

```bash
CyberWolfSec@htb[/htb]$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:12 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00018s latency).

PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      45837/tcp   mountd
|   100021  1,3,4      44629/tcp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
MAC Address: 00:00:00:00:00:00 (VMware)
```

Esto revela:

* Versiones RPC
* Servicios asociados (mountd, nlockmgr, nfs_acl)

---

## Uso de Scripts NSE para NFS

```bash
CyberWolfSec@htb[/htb]$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| nfs-ls: Volume /mnt/nfs
| PERMISSION  UID    GID    SIZE  TIME                 FILENAME
| rwxrwxrwx   65534  65534  4096  2021-09-19T15:28:17  .
| rw-r--r--   0      0      1872  2021-09-19T15:27:42  id_rsa
| rw-r--r--   0      0      348   2021-09-19T15:28:17  id_rsa.pub
| nfs-showmount:
|_  /mnt/nfs 10.129.14.0/24
```

Se puede:

* Listar archivos
* Ver permisos
* Identificar claves privadas

---

# 9. Enumeración con showmount

```bash
CyberWolfSec@htb[/htb]$ showmount -e 10.129.14.128

Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

---

# 10. Montaje Manual del Share

```bash
CyberWolfSec@htb[/htb]$ mkdir target-NFS
CyberWolfSec@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
CyberWolfSec@htb[/htb]$ cd target-NFS
CyberWolfSec@htb[/htb]$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

---

# 11. Análisis de Permisos

## Con nombres

```bash
CyberWolfSec@htb[/htb]$ ls -l mnt/nfs/

-rw-r--r-- 1 root     root     1872 Sep 19 17:27 id_rsa
```

## Con UID/GID

```bash
CyberWolfSec@htb[/htb]$ ls -n mnt/nfs/

-rw-r--r-- 1 0 0 1872 Sep 19 17:27 id_rsa
```

Si `root_squash` está activo, root no podrá modificar ciertos archivos.

---

# 12. Escalada de Privilegios vía NFS

Escenario típico:

1. Existe `no_root_squash`
2. Podemos montar el share
3. Creamos binario SUID como root
4. Ejecutamos desde el sistema remoto

Ejemplo conceptual:

```bash
cp /bin/bash ./bash-root
chmod +s bash-root
```

Si el servidor respeta UID 0 remoto → obtenemos shell root.

---

# 13. Desmontar el Share

```bash
CyberWolfSec@htb[/htb]$ cd ..
CyberWolfSec@htb[/htb]$ sudo umount ./target-NFS
```

---

# 14. Conclusiones Técnicas

NFS es:

* Extremadamente potente
* Simple de configurar
* Muy peligroso si se configura mal

Puntos críticos en pentesting:

✔ Enumerar puertos 111 y 2049
✔ Usar scripts nfs* de Nmap
✔ Revisar exportaciones
✔ Analizar UID/GID
✔ Verificar root_squash
✔ Buscar claves privadas
✔ Evaluar no_root_squash

NFS mal configurado puede equivaler a acceso root remoto sin autenticación real.

---

FIN DEL LIENZO
