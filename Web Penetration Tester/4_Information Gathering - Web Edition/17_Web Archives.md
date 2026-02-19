# Web Archives (Wayback Machine)

En el dinámico mundo digital, los sitios web cambian constantemente: páginas que desaparecen, secciones que se modifican, tecnologías que se reemplazan. Sin embargo, gracias a la **Wayback Machine** del Internet Archive, es posible retroceder en el tiempo y explorar cómo eran los sitios web en el pasado.

---

# ¿Qué es la Wayback Machine?

La **Wayback Machine** es un archivo digital de la World Wide Web y otros recursos de Internet.

Fue creada por la organización sin fines de lucro **Internet Archive** y archiva sitios web desde 1996.

Permite a los usuarios:

* Visualizar versiones antiguas de un sitio web.
* Consultar capturas históricas (snapshots).
* Analizar cambios en diseño, contenido y funcionalidad.

Cada versión archivada se denomina **capture** o **snapshot**.

---

# ¿Cómo funciona la Wayback Machine?

Opera de forma similar a un motor de búsqueda, pero en lugar de solo indexar contenido, almacena copias completas de las páginas.

Su funcionamiento puede dividirse en tres etapas:

---

## 1️⃣ Crawling

La Wayback Machine utiliza bots automatizados que:

* Navegan sistemáticamente la web.
* Siguen enlaces.
* Descargan copias completas de las páginas encontradas.

---

## 2️⃣ Archiving

Las páginas descargadas se almacenan junto con:

* HTML
* CSS
* JavaScript
* Imágenes
* Recursos asociados

Cada captura queda asociada a una **fecha y hora específica**, creando una instantánea histórica.

La frecuencia de archivado depende de:

* Popularidad del sitio.
* Frecuencia de actualización.
* Recursos disponibles del Internet Archive.

Algunos sitios se archivan varias veces por día; otros solo unas pocas veces al año.

---

## 3️⃣ Accessing

Los usuarios pueden:

1. Introducir una URL en la interfaz.
2. Seleccionar una fecha.
3. Visualizar cómo era el sitio en ese momento.

También es posible:

* Buscar términos dentro del contenido archivado.
* Descargar contenido para análisis offline.

---

# Limitaciones

* No todos los sitios están archivados.
* No todas las páginas de un sitio se capturan.
* Algunos propietarios solicitan exclusión del archivo.
* Puede haber recursos faltantes en ciertas capturas.

---

# Importancia en Web Reconnaissance

La Wayback Machine es una fuente extremadamente valiosa durante la fase de reconocimiento.

---

## 🔎 Descubrir Activos Ocultos

Permite encontrar:

* Directorios antiguos
* Subdominios olvidados
* Archivos eliminados
* Paneles administrativos antiguos

Estos recursos pueden no estar disponibles actualmente, pero podrían seguir existiendo en el servidor.

---

## 🔄 Analizar Cambios y Evolución

Comparando snapshots históricos se pueden detectar:

* Cambios en estructura
* Tecnologías utilizadas anteriormente
* Versiones antiguas vulnerables
* Eliminación de funcionalidades

Esto puede revelar patrones interesantes o errores de configuración.

---

## 🧠 Fuente de OSINT

El contenido archivado puede revelar:

* Empleados antiguos
* Correos electrónicos
* Estrategias de marketing
* Tecnologías usadas históricamente

---

## 🕵 Reconocimiento Pasivo

Acceder a snapshots archivados:

* No interactúa directamente con el servidor objetivo.
* No genera logs en la infraestructura actual del target.
* Es menos detectable.

---

# Ejemplo: Hack The Box en el Pasado

Si buscamos versiones antiguas de Hack The Box en la Wayback Machine y seleccionamos la captura más temprana disponible (por ejemplo 2017-06-10), podemos observar:

* Diseño inicial de la plataforma.
* Versión beta (0.8.7).
* Estructura original del sitio.
* Cambios significativos respecto a la versión actual.

Este tipo de análisis puede ser útil para:

* Identificar tecnologías usadas en el pasado.
* Detectar endpoints que ya no son visibles.
* Analizar evolución de la superficie de ataque.

---

# Metodología Recomendada

Durante un pentest:

1. Consultar la Wayback Machine para el dominio objetivo.
2. Revisar capturas más antiguas y más recientes.
3. Buscar rutas interesantes (admin, backup, api, dev).
4. Comparar cambios estructurales.
5. Correlacionar con resultados de crawling y Google Dorking.

---

# Conclusión

La Wayback Machine es una herramienta poderosa para el reconocimiento pasivo.

Permite:

* Analizar la historia digital de un objetivo.
* Descubrir recursos ocultos o eliminados.
* Obtener inteligencia sin interacción directa.

En combinación con crawling, fingerprinting, robots.txt y OSINT, ofrece una visión profunda y estratégica de la superficie de ataque del objetivo.
