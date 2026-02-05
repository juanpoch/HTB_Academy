# DNS (Domain Name System)

## Introducción

El **Domain Name System (DNS)** actúa como el **GPS de Internet**, permitiendo traducir nombres fáciles de recordar (como `www.example.com`) en direcciones numéricas precisas (como `192.0.2.1`) que las computadoras utilizan para comunicarse entre sí.

De la misma manera que un GPS convierte el nombre de un lugar en coordenadas geográficas, DNS convierte nombres de dominio legibles por humanos en **direcciones IP**.

Sin DNS, navegar por Internet sería como intentar moverse por una ciudad memorizando latitudes y longitudes: **ineficiente, propenso a errores y poco práctico**.

---

## ¿Por qué DNS es esencial?

Cuando escribimos un dominio en el navegador:

* Los humanos usamos **nombres**.
* Las computadoras entienden **números**.

DNS funciona como un **traductor automático**, permitiendo que ambos mundos se conecten de forma transparente. Sin este sistema, cada acceso a un sitio web requeriría conocer la IP exacta del servidor.

---

## Cómo funciona DNS

Supongamos que queremos acceder a `www.example.com`.

### 1. Consulta inicial

Al ingresar el dominio en el navegador, el sistema:

* Verifica primero su **caché local** (memoria).
* Si no encuentra la IP, envía la consulta a un **DNS Resolver** (normalmente provisto por el ISP o un resolver público como 8.8.8.8).

---

### 2. Búsqueda recursiva

Si el resolver no tiene la respuesta en caché, inicia una **búsqueda recursiva** dentro de la jerarquía DNS.

---

### 3. Root Name Server

El resolver consulta a un **Root Name Server**.

* No conoce la IP final.
* Indica qué **TLD Name Server** es responsable del dominio (por ejemplo `.com`).

---

### 4. TLD Name Server

El servidor TLD:

* Sabe qué **Authoritative Name Server** gestiona el dominio específico (`example.com`).
* Redirige la consulta hacia él.

---

### 5. Authoritative Name Server

Este servidor:

* Contiene la información definitiva del dominio.
* Devuelve la **dirección IP correcta**.

---

### 6. Respuesta al cliente

* El resolver devuelve la IP al equipo del usuario.
* La respuesta se **cachea** por un período determinado.

---

### 7. Conexión al servidor

Con la IP ya conocida, el navegador se conecta directamente al servidor web y el sitio se carga.

> 📸 **Acá podés pegar un diagrama del flujo de resolución DNS**.

---

## El archivo hosts

El **archivo hosts** es un archivo de texto que permite mapear manualmente nombres de dominio a direcciones IP, **saltándose completamente el proceso DNS**.

### Ubicación

* **Windows:** `C:\Windows\System32\drivers\etc\hosts`
* **Linux / macOS:** `/etc/hosts`

### Formato

```text
<IP Address>    <Hostname> [Alias]
```

Ejemplos:

```text
127.0.0.1       localhost
192.168.1.10    devserver.local
```

Los cambios tienen efecto inmediato y requieren permisos de administrador/root.

---

### Usos comunes del archivo hosts

* Redirigir dominios a servidores locales (desarrollo):

```text
127.0.0.1       myapp.local
```

* Probar conectividad:

```text
192.168.1.20    testserver.local
```

* Bloquear sitios no deseados:

```text
0.0.0.0         unwanted-site.com
```

---

## DNS como una carrera de relevos

El proceso DNS puede entenderse como una **carrera de relevos**:

1. El usuario entrega el dominio al resolver.
2. El resolver lo pasa al root server.
3. El root server lo pasa al TLD.
4. El TLD lo pasa al servidor autoritativo.
5. La IP vuelve por el mismo camino hasta el usuario.

Cada paso acerca un poco más al destino final.

---

## Conceptos clave de DNS

### Zona DNS

Una **zona DNS** es una porción del espacio de nombres administrada por una entidad específica.

Ejemplo:

* `example.com`
* `mail.example.com`
* `blog.example.com`

suelen pertenecer a la misma zona.

---

### Zone File

El **zone file** es un archivo de texto que define los **registros DNS** de una zona.

Ejemplo simplificado:

```zone
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. (
        2024060401
        3600
        900
        604800
        86400 )

@   IN NS ns1.example.com.
@   IN NS ns2.example.com.
@   IN MX 10 mail.example.com.
www IN A 192.0.2.1
mail IN A 198.51.100.1
ftp IN CNAME www.example.com.
```

---

## Componentes fundamentales de DNS

* **Domain Name:** nombre legible (ej: `www.example.com`).
* **IP Address:** identificador numérico (ej: `192.0.2.1`).
* **DNS Resolver:** traduce nombres a IPs.
* **Root Name Server:** punto más alto de la jerarquía DNS.
* **TLD Name Server:** gestiona dominios `.com`, `.org`, etc.
* **Authoritative Name Server:** contiene la información final del dominio.

---

## Tipos de registros DNS

| Tipo  | Nombre completo     | Descripción                              |
| ----- | ------------------- | ---------------------------------------- |
| A     | Address Record      | Mapea hostname a IPv4                    |
| AAAA  | IPv6 Address Record | Mapea hostname a IPv6                    |
| CNAME | Canonical Name      | Alias hacia otro hostname                |
| MX    | Mail Exchange       | Servidores de correo                     |
| NS    | Name Server         | Delegación de zona                       |
| TXT   | Text Record         | Información arbitraria (SPF, DKIM, etc.) |
| SOA   | Start of Authority  | Info administrativa de la zona           |
| SRV   | Service Record      | Servicios y puertos                      |
| PTR   | Pointer Record      | Resolución inversa                       |

---

## El campo "IN" en DNS

El valor **IN** indica la clase **Internet**, es decir, que el registro pertenece al protocolo IP.

Aunque existen otras clases (CH, HS), en la práctica moderna **IN es el estándar absoluto**.

---

## Importancia de DNS en Web Recon

DNS es una fuente crítica de información durante el reconocimiento web:

### Descubrimiento de activos

* Subdominios
* Servidores de correo
* Infraestructura de DNS

Un CNAME mal configurado puede apuntar a servidores obsoletos o vulnerables.

---

### Mapeo de infraestructura

Analizando registros DNS es posible:

* Identificar proveedores de hosting
* Detectar balanceadores de carga
* Comprender el flujo del tráfico

Esto permite localizar **puntos débiles o cuellos de botella**.

---

### Detección de cambios

Monitorear DNS en el tiempo puede revelar:

* Nuevos subdominios (`vpn.example.com`)
* Servicios internos expuestos
* Tecnologías utilizadas (ej: TXT con `_1password=`)

Estos cambios suelen indicar **nuevas superficies de ataque**.

---

## Conclusión

DNS no es solo un mecanismo de resolución de nombres, sino una **fuente estratégica de inteligencia** durante un pentest web.

Comprender cómo funciona y qué información expone permite ampliar el alcance del reconocimiento, descubrir activos ocultos y anticipar vectores de ataque que no serían visibles de otra manera.
