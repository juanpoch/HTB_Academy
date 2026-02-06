# Subdomain Bruteforcing

## Introducción

La **enumeración de subdominios por fuerza bruta** (*Subdomain Brute-Force Enumeration*) es una técnica **activa** muy efectiva para descubrir subdominios ocultos. Se basa en probar sistemáticamente nombres potenciales de subdominios contra un dominio objetivo, utilizando **wordlists predefinidas**.

Cuando se emplean listas bien seleccionadas, esta técnica puede **incrementar notablemente la cobertura** del reconocimiento y revelar activos que no aparecen en búsquedas pasivas.

---

## ¿Cómo funciona el brute-force de subdominios?

El proceso puede dividirse en **cuatro pasos clave**:

### 1) Selección de wordlist

La efectividad del brute-force depende en gran medida de la lista utilizada. Existen distintos enfoques:

* **Wordlists genéricas**
  Incluyen nombres comunes como `dev`, `staging`, `admin`, `blog`, `mail`, `test`.
  Son útiles cuando no se conoce el esquema de nombres del objetivo.

* **Wordlists específicas del objetivo**
  Adaptadas a la industria, tecnologías o patrones detectados previamente.
  Reducen ruido y falsos positivos.

* **Wordlists personalizadas**
  Construidas a partir de inteligencia previa (DNS, CT logs, nombres internos, tecnologías detectadas).

---

### 2) Iteración y generación de subdominios

Una herramienta o script recorre la wordlist y genera nombres completos como:

* `dev.example.com`
* `staging.example.com`
* `admin.example.com`

Cada entrada se prueba contra el dominio principal.

---

### 3) Resolución DNS

Para cada subdominio generado, se realiza una consulta DNS (generalmente **A** o **AAAA**) para verificar si resuelve a una IP válida.

---

### 4) Filtrado y validación

Si un subdominio resuelve correctamente:

* Se agrega a la lista de resultados
* Puede validarse adicionalmente accediendo vía HTTP/HTTPS

Este paso ayuda a confirmar que el subdominio **existe y está operativo**.

---

## Herramientas para Subdomain Bruteforcing

Existen múltiples herramientas especializadas para este tipo de enumeración:

| Herramienta     | Descripción                                                        |
| --------------- | ------------------------------------------------------------------ |
| [**dnsenum**](https://github.com/fwaeytens/dnsenum)     | Herramienta completa de enumeración DNS con soporte de brute-force |
| [**fierce**](https://github.com/mschwager/fierce)      | Enumeración recursiva con detección de wildcards                   |
| [**dnsrecon**](https://github.com/darkoperator/dnsrecon)    | Combina múltiples técnicas de reconocimiento DNS                   |
| [**amass**](https://github.com/owasp-amass/amass)       | Muy completa y activamente mantenida; integra múltiples fuentes    |
| [**assetfinder**](https://github.com/tomnomnom/assetfinder) | Simple y rápida, ideal para escaneos livianos                      |
| [**puredns**](https://github.com/d3mondev/puredns)     | Potente herramienta enfocada en resolución y filtrado eficiente    |

---

## dnsenum

**dnsenum** es una herramienta de línea de comandos escrita en Perl y ampliamente utilizada en tareas de reconocimiento DNS. Proporciona un conjunto integral de funcionalidades para analizar la infraestructura DNS de un dominio objetivo.

### Funcionalidades principales

* **Enumeración de registros DNS**: A, AAAA, NS, MX, TXT
* **Intentos automáticos de transferencia de zona**
* **Brute-force de subdominios** mediante wordlists
* **Google scraping** para descubrir subdominios indexados
* **Reverse DNS lookup** para identificar dominios asociados a una IP
* **Consultas WHOIS** para información de registro

---

## Ejemplo práctico con dnsenum

En este ejemplo se enumeran subdominios del objetivo `inlanefreight.com` utilizando una wordlist de **SecLists**.

### Comando utilizado

```bash
dnsenum --enum inlanefreight.com \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -r
```

### Explicación de los parámetros

* `dnsenum --enum inlanefreight.com`
  Indica el dominio objetivo y activa un conjunto de opciones estándar.

* `-f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt`
  Especifica la wordlist utilizada para el brute-force.
  *(La ruta puede variar según la instalación de SecLists).*

* `-r`
  Habilita **enumeración recursiva**, es decir, si se descubre un subdominio, dnsenum intentará enumerar subdominios de ese subdominio.

---

### Fragmento del output

```text
www.inlanefreight.com.        300  IN  A  134.209.24.248
support.inlanefreight.com.    300  IN  A  134.209.24.248
```

> 📸 **Acá pegá la captura del output completo de dnsenum**.

---

## Consideraciones de OPSEC

* El brute-force de subdominios es **ruidoso** y fácilmente detectable.
* Puede generar alertas en:

  * DNS logs
  * IDS/IPS
  * Servicios de protección perimetral

Buenas prácticas:

* Usar wordlists ajustadas al contexto
* Limitar la velocidad de consultas
* Priorizar técnicas pasivas antes de brute-force

---

## Conclusión

El **Subdomain Bruteforcing** es una técnica extremadamente poderosa para ampliar la superficie de ataque durante el Web Reconnaissance.

Cuando se combina con:

* Enumeración pasiva
* Validación manual
* Buen criterio de OPSEC

permite descubrir activos críticos que suelen quedar fuera del alcance del dominio principal, aportando un **valor real y tangible** al pentest web.
