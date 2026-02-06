
# DNS Zone Transfers

## Introducción

Si bien el **brute-force de subdominios** puede ser muy efectivo, existe una técnica **potencialmente más eficiente y menos ruidosa** para descubrir subdominios: los **DNS Zone Transfers**.

Este mecanismo, pensado para la **replicación legítima** de registros DNS entre servidores, puede convertirse en una **fuente masiva de información** cuando está mal configurado.

---

## ¿Qué es una Zone Transfer?

Una **DNS Zone Transfer** es una copia completa de **todos los registros DNS** de una zona (un dominio y sus subdominios) desde un servidor DNS hacia otro.

Su objetivo legítimo es:

* Mantener **consistencia** entre servidores primarios y secundarios
* Asegurar **redundancia** y **alta disponibilidad**

Sin embargo, si no se aplican controles de acceso adecuados, **cualquier tercero no autorizado** puede descargar el archivo completo de zona.

Esto puede revelar:

* Todos los subdominios
* Direcciones IP asociadas
* Registros de correo, servicios y configuraciones internas

---

## Cómo funciona una Zone Transfer

El proceso típico consta de los siguientes pasos:

1. **Solicitud de transferencia (AXFR)**
   El servidor secundario envía una solicitud de transferencia completa (*AXFR*) al servidor primario.

2. **Transferencia del registro SOA**
   El servidor primario responde con el registro **SOA (Start of Authority)**, que contiene información clave como el número de serie de la zona, lo que ayuda al servidor secundario a determinar si los datos de su zona están actualizados.

3. **Transmisión de registros DNS**
   Se transfieren todos los registros de la zona: A, AAAA, MX, NS, CNAME, TXT, SRV, etc.

4. **Finalización de la transferencia**
   El servidor primario indica que la transferencia fue completada.

5. **Acknowledgement (ACK)**
   El servidor secundario confirma la recepción correcta de la información.

<img width="975" height="608" alt="image" src="https://github.com/user-attachments/assets/dd1a8eb4-10e2-4547-b71e-27a3e2d6cb71" />


---

## La vulnerabilidad de Zone Transfer

En los primeros años de Internet, era común permitir **transferencias de zona abiertas**, ya que simplificaban la administración.

Este enfoque introdujo una vulnerabilidad crítica:

* Cualquier cliente podía solicitar una copia completa de la zona
* No existían restricciones de origen

Como resultado, un atacante podía obtener un **mapa completo de la infraestructura DNS** de la organización.

---

## Información expuesta en una Zone Transfer

Una transferencia de zona no autorizada puede revelar:

### Subdominios

* Subdominios no públicos
* Entornos de desarrollo y staging
* Paneles administrativos
* Servicios internos

---

### Direcciones IP

* IPs internas o externas
* Posibles objetivos para escaneos adicionales

---

### Registros DNS críticos

* Name Servers (NS)
* Servidores de correo (MX)
* Servicios específicos (SRV)
* Registros TXT con información sensible

Toda esta información reduce drásticamente la **incertidumbre del atacante**.

---

## Mitigación

Hoy en día, la mayoría de los servidores DNS están configurados correctamente para:

* Permitir transferencias **solo a servidores secundarios autorizados**
* Bloquear solicitudes AXFR desde clientes no confiables

Sin embargo, errores de configuración o prácticas obsoletas aún pueden provocar exposiciones.

Por este motivo, **probar una zone transfer (con autorización)** sigue siendo una técnica válida durante el reconocimiento.

---

## Explotación de Zone Transfers con dig

El comando `dig` permite solicitar una transferencia de zona completa.

### Comando de ejemplo

```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

Este comando:

* Solicita una transferencia AXFR
* Especifica el name server objetivo
* Indica el dominio a transferir

---

## Ejemplo práctico: zonetransfer.me

El dominio `zonetransfer.me` está diseñado específicamente para **demostrar los riesgos** de las zone transfers.

### Fragmento del output

```text
zonetransfer.me. 7200 IN SOA nsztm1.digi.ninja. robin.digi.ninja.
zonetransfer.me. 7200 IN MX 0 ASPMX.L.GOOGLE.COM.
canberra-office.zonetransfer.me. 7200 IN A 202.14.81.230
asfdbbox.zonetransfer.me. 7200 IN A 127.0.0.1
...
```

> 📸 **Acá pegá la captura completa del output de la zone transfer**.

Este resultado expone:

* Subdominios
* Registros de correo
* Direcciones IP
* Servicios internos

---

## Consideraciones de OPSEC

* Las solicitudes AXFR pueden ser **registradas y alertadas**
* Algunos servidores responden parcialmente o bloquean el intento
* Repetir intentos innecesarios aumenta la detección

Buenas prácticas:

* Probar transferencias solo una vez
* Validar previamente los name servers
* Priorizar técnicas pasivas antes de AXFR

---

## Conclusión

Las **DNS Zone Transfers** representan una de las vulnerabilidades históricas más críticas en DNS.

Aunque hoy son menos comunes, cuando están presentes permiten obtener:

* Un inventario completo de subdominios
* Información estructural de alto valor
* Un punto de partida sólido para fases posteriores del pentest

Por su **alto impacto y bajo esfuerzo**, verificar la posibilidad de una zone transfer debería formar parte de cualquier estrategia seria de Web Reconnaissance.
