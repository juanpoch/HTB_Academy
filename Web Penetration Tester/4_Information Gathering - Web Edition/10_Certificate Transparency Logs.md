# Certificate Transparency Logs

## Introducción

En el ecosistema de Internet, la **confianza** es un pilar fundamental. Uno de los mecanismos clave que sostienen esta confianza es el uso de **SSL/TLS**, que permite cifrar la comunicación entre un navegador y un servidor web.

En el centro de SSL/TLS se encuentran los **certificados digitales**, que validan la identidad de un sitio web. Sin embargo, el proceso de emisión de certificados no es infalible: pueden existir certificados mal emitidos, fraudulentos o directamente maliciosos.

Para mitigar este riesgo surge **Certificate Transparency (CT)**.

---

## ¿Qué son los Certificate Transparency Logs?

Los **Certificate Transparency Logs** son **registros públicos, inmutables (append-only)** que almacenan información sobre todos los certificados SSL/TLS emitidos por las Autoridades Certificadoras (CAs).

Cada vez que una CA emite un certificado:

* Debe enviarlo a **múltiples CT logs**
* Estos logs son mantenidos por **organizaciones independientes**
* Cualquiera puede inspeccionarlos

Pueden pensarse como un **registro global de certificados** emitidos en Internet.

---

## ¿Por qué existen los CT Logs?

Los CT logs cumplen varios objetivos críticos:

### Detección temprana de certificados fraudulentos

Permiten identificar rápidamente **certificados no autorizados** o mal emitidos para un dominio legítimo. Esto posibilita:

* Revocar certificados maliciosos
* Reducir ataques de impersonación o MITM

---

### Responsabilidad de las Certificate Authorities

Al ser públicos:

* Las CAs quedan expuestas si emiten certificados incorrectos
* Se fomenta el cumplimiento de estándares
* Se refuerza la confianza en el ecosistema PKI

---

### Fortalecimiento del Web PKI

Los CT logs introducen **auditoría pública** sobre la emisión de certificados, fortaleciendo la infraestructura de confianza que sostiene HTTPS.

---

## CT Logs y Web Reconnaissance

Desde el punto de vista del **reconocimiento web**, los CT logs son una **fuente extremadamente valiosa** para la enumeración de subdominios.

A diferencia de:

* brute-forcing
* wordlists
* fuzzing de nombres

los CT logs ofrecen **datos reales e históricos**, no basados en suposiciones.

### Ventajas clave para el pentesting

* Enumeración de subdominios **sin interactuar con el objetivo**
* Descubrimiento de subdominios **no guessables**
* Acceso a subdominios **antiguos o expirados**
* Ideal para descubrir:

  * entornos dev/staging
  * servicios legacy
  * aplicaciones olvidadas

---

## ¿Por qué los CT Logs son tan efectivos?

Los certificados SSL/TLS suelen incluir en su campo **SAN (Subject Alternative Name)**:

* Dominio principal
* Subdominios asociados

Esto hace que cada certificado emitido deje un **rastro histórico** de subdominios, incluso si:

* ya no existen
* no están en DNS
* no responden actualmente

---

## Herramientas para consultar CT Logs

Existen múltiples servicios para consultar CT logs. Dos de los más utilizados son:

| Herramienta | Características                                        | Casos de uso                              | Pros                 | Contras           |
| ----------- | ------------------------------------------------------ | ----------------------------------------- | -------------------- | ----------------- |
| **crt.sh**  | Interfaz web simple, búsqueda por dominio, muestra SAN | Enumeración rápida de subdominios         | Gratis, sin registro | Filtros limitados |
| **Censys**  | Motor de búsqueda avanzado, filtros por certificados   | Análisis profundo, correlación de activos | Muy potente, API     | Requiere cuenta   |

---

## crt.sh en la práctica

### Uso vía web

* Acceder a: [https://crt.sh](https://crt.sh)
* Buscar por dominio: `example.com`
* Revisar el campo **Name Value**

---

### Uso vía API (línea de comandos)

crt.sh también permite consultas automatizadas devolviendo resultados en formato JSON.

### Ejemplo: buscar subdominios "dev" de facebook.com

```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" \
| jq -r '.[] | select(.name_value | contains("dev")) | .name_value' \
| sort -u
```

### Explicación del comando

* `curl -s "https://crt.sh/?q=facebook.com&output=json"`
  Descarga los certificados asociados al dominio en formato JSON.

* `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`
  Filtra certificados cuyo SAN contiene la palabra `dev`.

* `sort -u`
  Ordena y elimina duplicados.

---

### Resultado de ejemplo

```text
*.dev.facebook.com
dev.facebook.com
secure.dev.facebook.com
newdev.facebook.com
...
```

> 📸 **Acá podés pegar la captura del output del comando CT log**.

---

## Limitaciones de los CT Logs

Aunque son extremadamente útiles, tienen algunas limitaciones:

* No garantizan que el subdominio esté activo
* Pueden incluir subdominios ya eliminados
* No revelan puertos, paths ni contenido

Por eso deben combinarse con:

* DNS resolution
* HTTP probing
* VHost discovery

---

## OPSEC y consideraciones éticas

* Las búsquedas en CT logs son **100% pasivas**
* No generan tráfico hacia el objetivo
* Son ideales para la fase inicial de recon

---

## Conclusión

Los **Certificate Transparency Logs** son una de las fuentes más poderosas y subestimadas para el Web Reconnaissance.

Su capacidad para revelar:

* subdominios reales
* información histórica
* activos olvidados

los convierte en una herramienta esencial para cualquier pentester que busque **ampliar la superficie de ataque sin levantar alertas**.

Integrar CT logs con técnicas activas permite construir una visión completa y precisa de la infraestructura del objetivo.
