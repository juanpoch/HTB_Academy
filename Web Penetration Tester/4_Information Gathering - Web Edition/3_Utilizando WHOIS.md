# Utilización de WHOIS

## Introducción

El protocolo **WHOIS** no solo sirve para consultar información técnica de dominios, sino que también es una herramienta clave en **investigaciones de seguridad reales**. A continuación se presentan distintos escenarios que ilustran cómo los datos WHOIS pueden aportar contexto, indicadores de riesgo y apoyo a la toma de decisiones durante un análisis de seguridad.

---

## Escenario 1: Investigación de Phishing

Un *email security gateway* detecta un correo sospechoso enviado a múltiples empleados de una empresa. El mensaje se hace pasar por el banco de la compañía y solicita a los destinatarios que hagan clic en un enlace para “actualizar información de la cuenta”.

Un analista de seguridad inicia la investigación realizando una consulta WHOIS sobre el dominio incluido en el enlace del correo.

### Hallazgos del WHOIS

* **Fecha de registro:** el dominio fue registrado hace apenas unos días.
* **Registrant:** la información del registrante se encuentra oculta mediante un servicio de privacidad.
* **Name Servers:** los servidores DNS están asociados a un proveedor de *bulletproof hosting* conocido por alojar infraestructura maliciosa.

### Análisis

La combinación de estos factores representa **múltiples señales de alerta**:

* Dominios muy recientes suelen estar asociados a campañas de phishing.
* El uso de servicios de anonimización dificulta la atribución.
* Infraestructura previamente vinculada a actividades maliciosas incrementa la sospecha.

### Resultado

El analista alerta al equipo de IT para:

* Bloquear el dominio a nivel corporativo.
* Advertir a los empleados sobre la campaña de phishing.

Además, se continúa la investigación sobre el proveedor de hosting y las direcciones IP asociadas, lo que puede revelar **dominios adicionales** utilizados por el mismo actor.

---

## Escenario 2: Análisis de Malware

Un investigador de seguridad analiza una nueva variante de malware que infectó múltiples sistemas. El malware se comunica con un servidor remoto para recibir comandos (*C2*) y exfiltrar información.

Para obtener más contexto sobre la infraestructura del atacante, se realiza una consulta WHOIS sobre el dominio del servidor C2.

### Hallazgos del WHOIS

* **Registrant:** dominio registrado a nombre de un individuo usando un servicio de email gratuito y anónimo.
* **Ubicación:** dirección del registrante en un país con alta prevalencia de cibercrimen.
* **Registrar:** registrador con historial de políticas laxas frente a abusos.

### Análisis

Estos indicadores sugieren que el servidor C2 se encuentra alojado en un entorno:

* Comprometido, o
* Del tipo *bulletproof hosting*, tolerante a actividades maliciosas.

### Resultado

El investigador utiliza los datos WHOIS para:

* Identificar al proveedor de hosting.
* Notificar formalmente la actividad maliciosa.

Esta acción puede derivar en el **desmantelamiento de la infraestructura** utilizada por el malware.

---

## Escenario 3: Reporte de Threat Intelligence

Una empresa de ciberseguridad realiza el seguimiento de un grupo de amenazas avanzado que apunta a instituciones financieras. Los analistas recopilan datos WHOIS de múltiples dominios utilizados en campañas previas.

### Patrones identificados

Al analizar los registros WHOIS, se observan los siguientes comportamientos:

* **Fechas de registro:** dominios creados en bloques, poco antes de ataques importantes.
* **Registrantes:** uso de alias y identidades falsas.
* **Name Servers:** reutilización de los mismos servidores DNS en distintos dominios.
* **Historial de baja:** dominios dados de baja tras ataques exitosos.

### Resultado

Estos patrones permiten construir un perfil detallado de las **Tácticas, Técnicas y Procedimientos (TTPs)** del grupo atacante.

El informe de *Threat Intelligence* incluye:

* Indicadores de Compromiso (IOCs)
* Infraestructura asociada
* Patrones temporales de registro

Este material puede ser utilizado por otras organizaciones para **detectar y bloquear ataques futuros**.

---

## Uso práctico del comando WHOIS

Antes de utilizar WHOIS, es necesario asegurarse de que la herramienta esté instalada en el sistema Linux.

### Instalación

```bash
sudo apt update
sudo apt install whois -y
```

---

## Ejemplo práctico: WHOIS sobre facebook.com

Consulta realizada:

```bash
whois facebook.com
```

Fragmento del resultado:

```text
Domain Name: FACEBOOK.COM
Registrar: RegistrarSafe, LLC
Creation Date: 1997-03-29
Registry Expiry Date: 2033-03-30
Name Server: A.NS.FACEBOOK.COM
Name Server: B.NS.FACEBOOK.COM
Name Server: C.NS.FACEBOOK.COM
Name Server: D.NS.FACEBOOK.COM
```

> 📸 **Acá pegá la captura del comando WHOIS ejecutado sobre facebook.com**.

---

## Análisis del resultado

### Registro del dominio

* **Registrar:** RegistrarSafe, LLC
* **Fecha de creación:** 1997-03-29
* **Fecha de expiración:** 2033-03-30

Esto indica que se trata de un dominio **antiguo y consolidado**, lo que refuerza su legitimidad.

---

### Propietario del dominio

* **Organización:** Meta Platforms, Inc.
* **Contacto:** Domain Admin

El resultado es consistente con lo esperado para una plataforma global como Facebook.

---

### Estado del dominio

Estados como:

* clientDeleteProhibited
* clientTransferProhibited
* serverUpdateProhibited

indican que el dominio cuenta con **protecciones activas contra modificaciones no autorizadas**, reflejando un fuerte control de seguridad.

---

### Name Servers

Los servidores DNS pertenecen al propio dominio facebook.com, lo que sugiere que **Meta administra su propia infraestructura DNS**, una práctica común en grandes organizaciones.

---

## Limitaciones de WHOIS

Aunque WHOIS aporta información valiosa, también presenta limitaciones:

* No suele exponer empleados individuales en grandes organizaciones.
* No revela vulnerabilidades técnicas directamente.
* Puede estar limitado por servicios de privacidad o regulaciones como GDPR.

Por este motivo, WHOIS debe utilizarse **en conjunto con otras técnicas de reconocimiento** para obtener una visión completa del objetivo.

---

## Conclusión

WHOIS es una herramienta fundamental dentro del **Information Gathering**, especialmente útil para:

* Evaluar legitimidad de dominios
* Detectar campañas maliciosas
* Analizar infraestructura de amenazas
* Enriquecer reportes de Threat Intelligence

Sin embargo, su verdadero valor surge cuando se **correlaciona con otras fuentes de información**, permitiendo construir un panorama más completo y accionable del entorno analizado.
