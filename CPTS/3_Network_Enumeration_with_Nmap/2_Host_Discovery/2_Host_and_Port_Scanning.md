# 🚀 Host and Port Scanning con Nmap
*Módulo: Network Enumeration with Nmap (HTB)*

Comprender **cómo Nmap realiza los escaneos**, cómo obtiene la información y cómo interpretar correctamente los resultados es esencial para cualquier pentester.

Después de confirmar que el objetivo está vivo, queremos obtener un **“mapa” más preciso del sistema**. La información clave que buscamos es:

- Puertos abiertos y sus servicios  
- Versiones de los servicios  
- Información adicional expuesta por los servicios  
- Sistema operativo

---

## 📌 Estados posibles de un puerto en Nmap

Nmap puede clasificar cada puerto en **uno de 6 estados**:

| Estado            | Descripción |
|------------------|------------|
| **open**         | Hay una conexión establecida al puerto. Puede ser una conexión TCP, un datagrama UDP o una asociación SCTP. |
| **closed**       | El puerto está cerrado. En TCP esto se ve porque la respuesta contiene un flag **RST**. Aun así, nos sirve para saber que el host está vivo. |
| **filtered**     | Nmap no puede determinar si el puerto está open o closed porque no recibe respuesta o recibe un error (por ejemplo, firewall). |
| **unfiltered**   | Solo aparece en escaneos **TCP ACK**. El puerto es accesible, pero Nmap no puede determinar si está open o closed. |
| **open\|filtered** | No se recibe respuesta. Puede estar abierto pero filtrado por un firewall o filtro de paquetes. Muy común en UDP. |
| **closed\|filtered** | Solo aparece en **IP ID idle scans**. Nmap no pudo decir si el puerto está cerrado o filtrado por un firewall. |

---

## 🔥 Descubriendo puertos TCP abiertos

Por defecto, Nmap:

- Escanea los **1000 puertos TCP más comunes**.
- Si se ejecuta como **root**, usa **SYN scan (-sS)**.
- Si NO es root, usa **Connect scan (-sT)**.

Podemos elegir los puertos con:

- Puertos específicos: `-p 22,25,80,139,445`  
- Rango: `-p 22-445`  
- Top ports: `--top-ports=10`  
- Todos los puertos: `-p-`  
- Escaneo rápido de 100 puertos más comunes: `-F`  

---

## 🧪 Escaneo de los Top 10 puertos TCP

```bash
sudo nmap 10.129.2.28 --top-ports=10
```
