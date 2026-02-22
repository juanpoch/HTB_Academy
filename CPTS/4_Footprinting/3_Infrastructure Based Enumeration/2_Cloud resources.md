# Cloud Resources

## Introducción

El uso de servicios en la nube como **AWS (Amazon Web Services)**, **GCP (Google Cloud Platform)** y **Microsoft Azure** se ha convertido en un componente esencial para la mayoría de las empresas modernas. Estas plataformas permiten centralizar la gestión de infraestructura, facilitar el acceso remoto y optimizar la escalabilidad de los servicios.

Sin embargo, aunque los proveedores de nube protegen su infraestructura a nivel central, esto **no elimina las vulnerabilidades derivadas de configuraciones incorrectas realizadas por los administradores**.

En muchos casos, los problemas comienzan con recursos de almacenamiento mal configurados, como:

* **S3 Buckets** (AWS)
* **Blobs** (Azure)
* **Cloud Storage** (GCP)

Si estos recursos permiten acceso sin autenticación debido a una mala configuración, pueden exponer información sensible.

---

# Company Hosted Servers – Cloud Resources

Durante la enumeración DNS, podemos identificar recursos alojados en la nube mediante resolución de subdominios.

Ejemplo práctico del curso:

```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

Salida obtenida:

```
blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```

Aquí observamos que una IP pertenece a:

```
s3-website-us-west-2.amazonaws.com
```

Esto indica que la empresa está utilizando almacenamiento en AWS.

Muchas veces estos recursos cloud se agregan a la lista DNS para facilitar el acceso administrativo interno, lo cual puede exponerse indirectamente durante el reconocimiento.

---

# Descubrimiento de Cloud Storage mediante Google Dorks

Una técnica muy utilizada es el uso de **Google Dorks** para localizar almacenamiento en la nube.

Ejemplos:

### Buscar AWS S3

```
intext:[empresa] inurl:amazonaws.com
```
<img width="1523" height="887" alt="image" src="https://github.com/user-attachments/assets/3fb1d735-469f-4381-bcdf-9885bd02f4ed" />

<img width="1523" height="887" alt="image" src="https://github.com/user-attachments/assets/a617b88a-04b5-4a2b-a33e-e569edaa7b57" />





### Buscar Azure Blob Storage

```
intext:[empresa] inurl:blob.core.windows.net
```

<img width="1523" height="887" alt="image" src="https://github.com/user-attachments/assets/c5a48db8-17e0-461a-8bf8-a7303f9908a8" />


<img width="1523" height="887" alt="image" src="https://github.com/user-attachments/assets/c8ff1d63-489e-4976-a2b4-ffbe92f97c4e" />


Estos filtros permiten encontrar:

* PDFs
* Documentos de texto
* Presentaciones
* Archivos de configuración
* Código fuente

Muchas veces Google indexa estos archivos si el bucket es público.

---

# Revisión del Código Fuente del Sitio Web

Otra técnica importante consiste en inspeccionar el **código fuente HTML** del sitio objetivo.

Frecuentemente se observan recursos externos cargados desde servicios cloud, por ejemplo:

* Imágenes
* Archivos JavaScript
* CSS

Estos pueden provenir de dominios como:

```
blob.core.windows.net
amazonaws.com
storage.googleapis.com
```

El uso de almacenamiento externo suele realizarse para aliviar carga del servidor principal, pero puede revelar infraestructura adicional.

---

# Uso de Servicios de Terceros – Domain.glass

Herramientas como **domain.glass** permiten analizar:

* Infraestructura DNS
* Certificados SSL
* IPs asociadas
* Servicios externos
* Evaluación de seguridad (ej. estado Cloudflare)

En el ejemplo del curso, se observa que Cloudflare clasifica el dominio como "Safe".

Esto indica que:

* Existe una capa de protección tipo gateway
* La empresa utiliza servicios CDN / WAF
* Hay una segunda capa defensiva

Esto debe anotarse dentro del análisis de superficie de ataque.

---

# Descubrimiento de Buckets con GrayHatWarfare

GrayHatWarfare es una plataforma que permite buscar buckets públicos de:

* AWS
* Azure
* GCP

Permite:

* Filtrar por tipo de archivo
* Ver cantidad de archivos
* Descubrir buckets relacionados con la empresa

Una vez identificado un bucket vía Google, se puede pivotear hacia GrayHatWarfare para descubrir más contenido.

---

# Uso de Abreviaturas Empresariales

Muchas empresas utilizan abreviaturas internas dentro de su infraestructura.

Ejemplo:

* Nombre completo de empresa
* Acrónimo interno
* Nombre reducido

Estos términos pueden utilizarse como palabras clave en búsquedas OSINT para descubrir nuevos recursos cloud.

---

# Filtración de Claves SSH Privadas

Uno de los escenarios más críticos ocurre cuando empleados suben por error archivos sensibles a un bucket público.

Ejemplo observado:

* id_rsa
* id_rsa.pub

Si un bucket contiene una clave privada SSH como:

```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

Esto puede permitir a un atacante:

* Descargar la clave
* Conectarse vía SSH
* Acceder a uno o múltiples servidores
* Evadir autenticación por contraseña

Este tipo de error puede comprometer gravemente la infraestructura.

---

# Conclusiones Técnicas

1. La nube no es insegura por diseño, pero las configuraciones incorrectas sí lo son.
2. La enumeración DNS puede revelar infraestructura cloud.
3. Google Dorking es una técnica extremadamente poderosa para detectar almacenamiento público.
4. El análisis del código fuente permite descubrir recursos externos.
5. Herramientas como Domain.glass y GrayHatWarfare enriquecen el reconocimiento pasivo.
6. La exposición de claves privadas SSH es un hallazgo crítico.

---

# Impacto en un Pentest

Durante una fase de reconocimiento pasivo, el descubrimiento de recursos cloud mal configurados puede permitir:

* Acceso a documentos internos
* Descubrimiento de credenciales
* Obtención de claves privadas
* Enumeración de infraestructura adicional
* Escalada posterior hacia acceso remoto

El análisis de recursos en la nube es una parte fundamental del OSINT moderno y del pre-engagement reconnaissance.
