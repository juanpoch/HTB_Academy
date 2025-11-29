# 🧠 Nmap Scripting Engine (NSE)

*Módulo: Network Enumeration with Nmap (HTB)*

El **Nmap Scripting Engine (NSE)** es una de las funciones más potentes de Nmap.
Permite escribir y ejecutar **scripts en Lua** para interactuar con servicios de red y extender las capacidades del escáner.

Con NSE podemos:

* Obtener más información de los servicios.
* Detectar vulnerabilidades conocidas.
* Automatizar tareas de enumeración, fuerza bruta, explotación, etc.

---

## 🗂 Categorías de scripts NSE

Los scripts están agrupados en **14 categorías** principales:

| Categoría   | Descripción                                                                                                          |
| ----------- | -------------------------------------------------------------------------------------------------------------------- |
| `auth`      | Descubrimiento / prueba de credenciales de autenticación.                                                            |
| `broadcast` | Descubrimiento de hosts mediante broadcast; los hosts encontrados se pueden añadir automáticamente a otros escaneos. |
| `brute`     | Ataques de fuerza bruta contra servicios (login con listas de usuarios/contraseñas).                                 |
| `default`   | Scripts por defecto que se ejecutan con `-sC`.                                                                       |
| `discovery` | Descubrimiento/identificación de servicios accesibles.                                                               |
| `dos`       | Prueban vulnerabilidades de **denial of service** (pueden dañar servicios).                                          |
| `exploit`   | Intentan explotar vulnerabilidades conocidas.                                                                        |
| `external`  | Usan servicios externos para enriquecer información.                                                                 |
| `fuzzer`    | Envían entradas anómalas para detectar fallos (fuzzing).                                                             |
| `intrusive` | Scripts potencialmente intrusivos que pueden impactar el sistema.                                                    |
| `malware`   | Buscan indicios de infección por malware.                                                                            |
| `safe`      | Scripts no intrusivos ni destructivos.                                                                               |
| `version`   | Extienden la detección de versiones (`-sV`).                                                                         |
| `vuln`      | Buscan vulnerabilidades específicas.                                                                                 |

---

## ⚙️ Formas de ejecutar scripts NSE

### 1. Scripts por defecto (`-sC`)

```bash
sudo nmap <target> -sC
```

---

### 2. Ejecutar una categoría completa

```bash
sudo nmap <target> --script <category>
```

Ejemplo:

```bash
sudo nmap <target> --script vuln
```

---

### 3. Ejecutar scripts específicos

```bash
sudo nmap <target> --script <script-name>,<script-name>
```

---

## 📬 Ejemplo: Enumeración sobre SMTP (banner y comandos)

```bash
sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
```

Salida:

```
PORT   STATE SERVICE
25/tcp open  smtp
|_banner: 220 inlane ESMTP Postfix (Ubuntu)
|_smtp-commands: inlane, PIPELINING, SIZE, VRFY, ETRN, STARTTLS, ...
```

### ¿Qué aporta cada script?

* **`banner`** → Obtiene el banner del servicio (ej.: Postfix en Ubuntu).
* **`smtp-commands`** → Enumera comandos soportados (útil para VRFY / STARTTLS, etc.).

---

## 🧬 Escaneo agresivo (`-A`)

Incluye:

* `-sV` (detección de servicios)
* `-O` (detección de OS)
* `--traceroute`
* Scripts por defecto (`-sC`)

Ejemplo:

```bash
sudo nmap 10.129.2.28 -p 80 -A
```

Salida relevante:

```
Apache httpd 2.4.29 ((Ubuntu))
WordPress 5.3.4
Título: blog.inlanefreight.com
Posibles kernels: Linux 2.6.x – 4.x
```

> ⚠️ Es ruidoso. Puede disparar IDS/IPS.

---

## 🛡️ Vulnerability Assessment con scripts `vuln`

```bash
sudo nmap 10.129.2.28 -p 80 -sV --script vuln
```

Salida relevante:

```
/wp-login.php: Possible admin folder
WordPress version: 5.3.4
Usuario encontrado: admin
CVE-2019-0211, CVE-2018-1312, ...
```

Scripts destacados:

* `http-enum` → Descubre rutas interesantes.
* `http-wordpress-users` → Enumera usuarios de WordPress.
* `vulners` → Devuelve CVEs relacionadas con el servicio detectado.

---

## 📚 Referencia oficial NSE

👉 [https://nmap.org/nsedoc/index.html](https://nmap.org/nsedoc/index.html)

---

## 🧭 Flujo recomendado de enumeración

1. **Escaneo rápido de puertos**

```bash
sudo nmap -F <target>
```

2. **Detección de servicios**

```bash
sudo nmap -sV -p 22,25,80 <target>
```

3. **Enumeración específica**

```bash
sudo nmap -p 25 --script banner,smtp-commands <target>
sudo nmap -p 80 --script http-enum,http-title <target>
```

4. **Detección de vulnerabilidades**

```bash
sudo nmap -p 80 -sV --script vuln <target>
```

5. **Escaneo agresivo (opcional)**

```bash
sudo nmap -A <target>
```


---


### Preguntas

#### Utilice NSE y sus scripts para encontrar la bandera que contiene uno de los servicios y enviarla como respuesta.


`Pista`: Los servidores web se encuentran entre los servicios más atacados porque son accesibles a los usuarios y presentan un alto potencial de ataque.


Hacemos un escaneo de los top 1000 puertos para identificar puertos abiertos:

