# Protocolo RC4

## Introducción

RC4 (Rivest Cipher 4 o Ron's Code 4) es un algoritmo de cifrado de flujo ampliamente utilizado en la criptografía moderna, especialmente durante las décadas de 1990 y 2000. Fue diseñado en 1987 por Ron Rivest para RSA Security. Su popularidad se debió a su eficiencia, facilidad de implementación en software y velocidad. Sin embargo, vulnerabilidades encontradas en su diseño y uso práctico llevaron a su desuso en contextos de alta seguridad.

---

## Características del Algoritmo

* **Tipo:** Cifrado por flujo (stream cipher)
* **Tamaño de clave:** Variable, entre 40 y 2048 bits (64 o 128 bits eran comunes)
* **Velocidad:** Muy rápido, especialmente en implementaciones software
* **Estado interno:** Vector de 256 bytes (S-box) y dos índices (i, j)

---

## Funcionamiento

RC4 opera mediante dos fases principales:

### 1. Inicialización del Estado (KSA - Key Scheduling Algorithm)

Se mezcla un vector S de 256 bytes (S-box) utilizando la clave proporcionada. Esto genera un estado interno pseudoaleatorio.

```python
for i in range(256):
    S[i] = i
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]
```

### 2. Generación de Keystream (PRGA - Pseudo-Random Generation Algorithm)

Se genera un flujo de claves pseudoaleatorias que se combinan con el texto plano mediante una operación XOR.

```python
i = j = 0
while True:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    K = S[(S[i] + S[j]) % 256]
    yield K
```

---

## Vulnerabilidades

1. **Sesgos en el Keystream:** RC4 no genera una secuencia perfectamente aleatoria. Hay patrones y correlaciones detectables, lo que permite ciertos ataques criptográficos.
2. **Ataques en implementaciones como WEP:** WEP (Wired Equivalent Privacy) usaba RC4 con vectores de inicialización (IVs) predecibles y cortos (24 bits), lo que facilitaba la reutilización de claves y ataques como el FMS (Fluhrer, Mantin, Shamir).
3. **Ataques en TLS:** Investigadores descubrieron formas de filtrar información sensible (como cookies) cuando RC4 se usaba en HTTPS. Esto llevó a la prohibición de su uso en TLS por parte de la IETF (RFC 7465).

---

## Aplicaciones Históricas

* **WEP:** El protocolo de seguridad Wi-Fi original dependía de RC4. Debido a su debilidad, WEP fue reemplazado por WPA y posteriormente WPA2.
* **WPA (TKIP):** Aunque mejoró sobre WEP, WPA también utilizó RC4 combinado con TKIP (Temporal Key Integrity Protocol).
* **SSL/TLS:** Algunas versiones tempranas de SSL y TLS usaban RC4 como opción de cifrado por su rapidez.

---

## Estado Actual

Hoy en día, RC4 está considerado inseguro y obsoleto. Fue formalmente desaprobado para uso en TLS con la publicación de la RFC 7465 en 2015.

> **Recomendación:** Evitar completamente su uso en cualquier entorno moderno. Se prefiere AES (Advanced Encryption Standard) para cifrado seguro.

---

## Herramientas que Aprovechan Debilidades de RC4

* **Aircrack-ng:** Permite capturar paquetes WEP y realizar ataques de clave usando debilidades de RC4.
* **Wireshark:** Puede usarse para visualizar patrones de cifrado en tráfico Wi-Fi antiguo.
* **Hashcat:** Algunas versiones pueden usar vectores de ataque a claves derivadas de RC4.

---

## Conclusión

RC4 fue alguna vez una pieza clave de la criptografía aplicada, pero su mal diseño y uso inadecuado en protocolos como WEP lo convirtieron en un ejemplo de por qué el cifrado debe ser analizado rigurosamente. Comprender RC4 y sus vulnerabilidades es esencial para cualquier profesional de ciberseguridad, especialmente en contextos de pentesting Wi-Fi.

---
