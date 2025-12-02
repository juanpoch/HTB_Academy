#  Metodología de Enumeración



---

## 1. Introducción a la Metodología de Enumeración

Los procesos complejos, como un pentest, requieren una **metodología estandarizada**. Sin una guía clara, es fácil omitir pasos o repetir acciones sin sentido. Muchos pentesters siguen **hábitos personales**, pero eso no constituye una metodología formal.

La enumeración es dinámica, pero necesitamos un marco que permita adaptarnos al entorno sin perder el rumbo. Para eso, HTB propone una **metodología de 6 capas**, dividida en tres niveles generales:

* **Infrastructure-Based Enumeration**
* **Host-Based Enumeration**
* **OS-Based Enumeration**

Estas capas representan "muros" o límites que debemos atravesar para acercarnos al objetivo.

---

## 2. Metodología en 6 Capas (Layers)

La metodología utiliza **capas concéntricas** que representan barreras a superar. Cada capa contiene información específica que debemos identificar.

<img width="1248" height="701" alt="image" src="https://github.com/user-attachments/assets/97464bd2-95df-4037-a125-439cf96c324d" />

---

## 🟦 Capa 1: Internet Presence

**Objetivo:** identificar la presencia pública del objetivo.

Incluye:

* Dominios
* Subdominios
* vHosts
* ASN
* Netblocks
* IPs públicas
* Instancias cloud
* Controles de seguridad (Cloudflare, WAF)

> Es el primer mapa del terreno: todo lo que la organización expone hacia Internet.

---

## 🟩 Capa 2: Gateway

**Objetivo:** comprender las medidas defensivas y la posición del objetivo dentro de la red.

Componentes comunes:

* Firewalls
* DMZ
* IPS/IDS
* EDR
* Proxies
* NAC
* Segmentación de red
* VPN
* Cloudflare / WAF

> Aquí entendemos qué tan protegido está el objetivo y cómo podríamos evitar o analizar esas defensas.

---

## 🟨 Capa 3: Accessible Services

**Objetivo:** enumerar y comprender todos los servicios accesibles.

Datos clave:

* Tipo de servicio
* Funcionalidad
* Configuración
* Puerto
* Versión
* Interfaz expuesta

> Cada servicio está allí por una razón. Comprender esa razón es fundamental para una explotación efectiva.

Esta es la capa principal tratada en este módulo.

---

## 🟧 Capa 4: Processes

**Objetivo:** entender cómo los servicios procesan información.

Analizamos:

* PID
* Datos procesados
* Tareas
* Fuente
* Destino

> La comunicación interna entre procesos revela dependencias, flujos de datos y puntos débiles que no siempre son visibles externamente.

---

## 🟫 Capa 5: Privileges

**Objetivo:** comprender permisos, roles y privilegios.

Incluye:

* Grupos
* Usuarios
* Permisos
* Restricciones
* Variables de entorno

> Muchos fallos críticos provienen de configuraciones incorrectas o privilegios excesivos, especialmente en Active Directory.

---

## 🟥 Capa 6: OS Setup

**Objetivo:** estudiar el sistema operativo y su configuración interna.

Elementos clave:

* Tipo de sistema operativo
* Nivel de parches
* Configuración de red
* Archivos de configuración
* Archivos sensibles
* Variables del entorno del OS

> Esta capa revela la calidad del trabajo del equipo de IT y la postura interna de seguridad.

---

## 3. Metáfora del Laberinto

La metodología puede visualizarse como un **laberinto**. Cada capa es un “muro” con múltiples posibles entradas.

Los cuadrados en el diagrama representan **vulnerabilidades** (gaps).

Puntos clave:

* No todos los gaps llevan al interior.
* Se debe priorizar qué caminos explorar según el tiempo disponible.
* En un pentest siempre existe la posibilidad de más vulnerabilidades que no descubrimos.

La historia del ataque a **SolarWinds** muestra que un atacante con meses de estudio del entorno puede descubrir vectores que un pentest típico no llega a ver.

---

## 4. Aplicación Práctica: Pentest Externo Black Box

Cuando comienza un engagement externo:

### **Capa 1: Internet Presence**

Encontramos todos los activos posibles.

### **Capa 2: Gateway**

Descubrimos defensas y arquitectura.

### **Capa 3: Accessible Services**

Analizamos servicios, funciones y configuraciones.

### **Capa 4: Processes**

Comprendemos tarea, origen y destino.

### **Capa 5: Privileges**

Estudiamos permisos y usuarios.

### **Capa 6: OS Setup**

Investigamos el sistema operativo y su configuración.

Cada capa nos acerca más al núcleo de la infraestructura.

---

## 5. Metodología en la Práctica

Una metodología no es una lista de comandos (eso es un **cheat sheet**).
Es un **marco sistemático** para explorar y comprender un objetivo.

El cómo se obtiene cada dato es dinámico: herramientas cambian, tecnologías evolucionan. Lo importante es:

* Seguir la estructura
* Adaptarse al contexto
* Mantener un pensamiento analítico

> La metodología guía. Las herramientas ejecutan.

---

## 6. Conclusión

Dominar esta metodología permite:

* Evitar omisiones
* Priorizar rutas útiles
* Organizar el trabajo
* Adaptarse a cada entorno
* Mantener enfoque profesional


---
