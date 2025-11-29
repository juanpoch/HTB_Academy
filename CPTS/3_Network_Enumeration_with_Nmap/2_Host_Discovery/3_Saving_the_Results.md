# 📝 Saving the Results — Guardando Resultados en Nmap

*Módulo: Network Enumeration with Nmap (HTB)*

Durante un pentest, **siempre debemos guardar los resultados de cada escaneo**. Esto permite:

* Comparar diferentes métodos de escaneo.
* Documentar hallazgos.
* Generar reportes técnicos y no técnicos.

Nmap permite guardar la salida en **3 formatos distintos**, además de una opción para guardarlos todos a la vez.

---

## 📦 Formatos de salida de Nmap

| Formato                | Flag  | Extensión                 | Descripción                                                                 |
| ---------------------- | ----- | ------------------------- | --------------------------------------------------------------------------- |
| **Normal**             | `-oN` | `.nmap`                   | Salida estándar, legible por humanos.                                       |
| **Grepable**           | `-oG` | `.gnmap`                  | Formato apto para usar con herramientas como `grep`, `awk`, `cut`, etc.     |
| **XML**                | `-oX` | `.xml`                    | Salida estructurada para análisis automático y generación de reportes HTML. |
| **Todos los formatos** | `-oA` | `.nmap`, `.gnmap`, `.xml` | Guarda simultáneamente en los 3 formatos.                                   |

---

## 🔥 Guardar resultados en todos los formatos (`-oA`)

```bash
sudo nmap 10.129.2.28 -p- -oA target
```

Salida resumida:

```text
Host is up (0.0091s latency).
Not shown: 65525 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
```

### Opciones usadas

| Opción       | Descripción                                                             |
| ------------ | ----------------------------------------------------------------------- |
| `-p-`        | Escanea **todos los puertos** (1–65535).                                |
| `-oA target` | Guarda los resultados como `target.nmap`, `target.gnmap`, `target.xml`. |

Al no usar ruta absoluta, los archivos se guardan en el **directorio actual**.

---

## 📁 Archivos generados

```bash
ls
```

Salida:

```text
target.gnmap  target.xml  target.nmap
```

---

## 📘 Normal Output (`.nmap`)

El archivo más legible para humanos:

```bash
cat target.nmap
```

Ejemplo de contenido:

```text
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
80/tcp open  http
```

Simple, claro y listo para informes técnicos.

---

## 🔍 Grepable Output (`.gnmap`)

Ideal para automatización:

```bash
cat target.gnmap
```

Salida típica:

```text
Host: 10.129.2.28 () Ports: 22/open/tcp//ssh///, 25/open/tcp//smtp///, 80/open/tcp//http///
```

Este formato permite hacer cosas como:

```bash
grep "/open/" target.gnmap | cut -d ":" -f 2
```

---

## 🧬 XML Output (`.xml`)

Formato estructurado para herramientas automatizadas.

```bash
cat target.xml
```

Permite integrar resultados con:

* scripts personalizados
* herramientas de análisis
* dashboards
* generadores de reportes

Ejemplo de un fragmento:

```xml
<port protocol="tcp" portid="22">
  <state state="open" reason="syn-ack" />
  <service name="ssh" />
</port>
```

---

## 🌐 Generar reportes HTML con `xsltproc`

A partir de la salida XML, Nmap permite generar un **reporte HTML legible y presentable**, ideal para clientes o documentación.

```bash
xsltproc target.xml -o target.html
```

Luego simplemente abrimos `target.html` en el navegador.

### Ejemplo de reporte generado

<img width="982" height="462" alt="image" src="https://github.com/user-attachments/assets/3625eca7-df61-4517-8818-1db197d2edd4" />


> "Nmap scan report for IP 10.10.10.28 shows open ports: 22 (SSH), 25 (SMTP), 80 (HTTP). Scanned on June 16, 2020."

---

## 📚 Referencia oficial

Más información sobre formatos de salida:
👉 [https://nmap.org/book/output.html](https://nmap.org/book/output.html)

---

Si querés, a continuación puedo preparar un lienzo separado solo con ejemplos prácticos para grep, automatización y scripting sobre `.gnmap` y `.xml`. ¿Querés eso también?
