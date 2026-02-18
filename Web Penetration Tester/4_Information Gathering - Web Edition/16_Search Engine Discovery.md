# Search Engine Discovery (OSINT)

Los motores de búsqueda son nuestras guías en el vasto ecosistema de Internet. Sin embargo, más allá de responder consultas cotidianas, también almacenan una enorme cantidad de información indexada que puede ser extremadamente valiosa durante la fase de reconocimiento web.

Esta práctica se conoce como **Search Engine Discovery** u **OSINT (Open Source Intelligence)**.

Consiste en utilizar motores de búsqueda como herramientas estratégicas para descubrir información sobre:

* Sitios web objetivo
* Organizaciones
* Empleados
* Infraestructura tecnológica
* Documentos públicos

---

# ¿Por qué es importante en Web Recon?

## 🌍 Open Source

La información es públicamente accesible.
No requiere interacción directa con el objetivo.

---

## 📚 Amplitud de Información

Los motores de búsqueda indexan una gran porción de la web, incluyendo:

* Documentos PDF
* Backups expuestos
* Páginas olvidadas
* Subdominios

---

## 🧩 Facilidad de Uso

No requiere herramientas complejas ni explotación activa.

---

## 💰 Costo Cero

Es completamente gratuito.

---

# Aplicaciones en Seguridad

La información obtenida puede utilizarse para:

* Security Assessment → Identificar datos expuestos.
* Competitive Intelligence → Analizar competidores.
* Threat Intelligence → Detectar amenazas emergentes.
* Investigación periodística.

⚠ Limitación: Los motores de búsqueda no indexan todo y algunos datos pueden estar protegidos o no ser accesibles públicamente.

---

# Search Operators

Los **Search Operators** son comandos especiales que permiten realizar búsquedas más precisas.

---

## Operadores Fundamentales

| Operator  | Descripción                               | Ejemplo                       | Descripción del Ejemplo                     |
| --------- | ----------------------------------------- | ----------------------------- | ------------------------------------------- |
| site:     | Limita resultados a un dominio específico | site:example.com              | Muestra páginas públicas del dominio        |
| inurl:    | Busca términos en la URL                  | inurl:login                   | Encuentra páginas con "login" en la URL     |
| filetype: | Busca tipos de archivo específicos        | filetype:pdf                  | Encuentra PDFs descargables                 |
| intitle:  | Busca términos en el título               | intitle:"confidential report" | Encuentra títulos con esa frase             |
| intext:   | Busca términos en el contenido            | intext:"password reset"       | Encuentra páginas con esa frase en el texto |
| cache:    | Muestra versión cacheada                  | cache:example.com             | Ver versión anterior almacenada             |
| related:  | Busca sitios similares                    | related:example.com           | Encuentra páginas similares                 |
| info:     | Muestra información básica del dominio    | info:example.com              | Muestra detalles generales                  |
| define:   | Define un término                         | define:phishing               | Devuelve definiciones                       |

---

## Operadores Avanzados

| Operator    | Descripción                                      | Ejemplo                             |
| ----------- | ------------------------------------------------ | ----------------------------------- |
| AND         | Requiere que todos los términos estén presentes  | site:example.com AND inurl:admin    |
| OR          | Amplía resultados con cualquiera de los términos | "linux" OR "ubuntu"                 |
| NOT o -     | Excluye términos                                 | site:bank.com -inurl:login          |
| *           | Comodín                                          | filetype:pdf user* manual           |
| ..          | Rango numérico                                   | "price" 100..500                    |
| " "         | Frase exacta                                     | "information security policy"       |
| allintext:  | Todos los términos en el cuerpo                  | allintext:admin password reset      |
| allinurl:   | Todos los términos en URL                        | allinurl:admin panel                |
| allintitle: | Todos los términos en título                     | allintitle:confidential report 2023 |

---

# Google Dorking

También conocido como **Google Hacking**, consiste en combinar operadores para descubrir información sensible.

---

## 🔐 Encontrar páginas de login

```
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin)
```

---

## 📂 Identificar archivos expuestos

```
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
```

---

## ⚙ Descubrir archivos de configuración

```
site:example.com inurl:config.php
site:example.com (ext:conf OR ext:cnf)
```

---

## 🗄 Localizar backups de base de datos

```
site:example.com inurl:backup
site:example.com filetype:sql
```

---

# Valor Estratégico

Google Dorking permite:

* Detectar credenciales expuestas.
* Encontrar archivos sensibles indexados.
* Descubrir endpoints no enlazados.
* Mapear infraestructura indirectamente.

---

# Enfoque Profesional

Durante un pentest, una estrategia común es:

1. Enumerar dominios y subdominios con `site:`.
2. Buscar archivos sensibles con `filetype:`.
3. Buscar endpoints administrativos con `inurl:`.
4. Combinar operadores para reducir ruido.
5. Correlacionar hallazgos con crawling y fingerprinting.

---

# Conclusión

Search Engine Discovery es una técnica poderosa dentro del reconocimiento pasivo.

Permite:

* Obtener información sin interactuar directamente con el objetivo.
* Descubrir datos expuestos accidentalmente.
* Identificar vectores potenciales de ataque.

Cuando se combina con crawling, robots.txt y análisis de .well-known URIs, se convierte en una herramienta esencial para construir un mapa completo de la superficie de ataque.
