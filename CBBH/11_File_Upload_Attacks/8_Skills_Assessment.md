# Skills Assessment - File Upload Attacks

You are contracted to perform a penetration test for a company's e-commerce web application. The web application is in its early stages, so you will only be testing any file upload forms you can find.

Try to utilize what you learned in this module to understand how the upload form works and how to bypass various validations in place (if any) to gain remote code execution on the back-end server.

## Extra Exercise

Try to note down the main security issues found with the web application and the necessary security measures to mitigate these issues and prevent further exploitation.

## Question

Try to exploit the upload form to read the flag found at the root directory "/".

`Hint`: Try to fuzz for non-blacklisted extensions, and for allowed content-type headers. If you are unable to locate the uploaded files, try to read the source code to find the uploads directory and the naming scheme.

---


Inspeccionando el código fuente, no podemos divisar el directorio de carga, pero observando el archivo `/contact/script.js`, encontramos el nombre del archivo del código fuente del backend (`/contact/upload.php`), que se está utilizando para cargar archivos, muy posiblemente ahí se encuentre información sensible como whitelist, blacklist, directorio de carga y otras operaciones con los archivos subidos:
![image](https://github.com/user-attachments/assets/34f321bd-57b0-4bf0-a5e3-1345f66eca53)

---

# Descripción del flujo normal de carga

Intentamos subir una imagen `.png` común:
![image](https://github.com/user-attachments/assets/929f061e-e5a8-451c-85af-ae684324681a)

Tramita esta petición `POST`:
![image](https://github.com/user-attachments/assets/610d2f51-cfd3-4602-838f-3e67f2eb812c)

Luego hacemos click en `Submit`:
![image](https://github.com/user-attachments/assets/d71ffabf-9610-4a68-970f-f67e019b7bb9)

![image](https://github.com/user-attachments/assets/955d45b7-8222-4d26-a268-86de780d2b15)

Tramita:
![image](https://github.com/user-attachments/assets/975adcae-a4b4-4c3a-993f-1aa855a08f6d)

---


Realizamos un fuzzing de `Content-Type` header utilizando la lista `web-all-contents-types.txt` de Seclists:
![image](https://github.com/user-attachments/assets/e08acc07-264f-43bb-97a1-58d917560eaf)


![image](https://github.com/user-attachments/assets/3d07536c-0b40-45b4-b696-56c0d83b72fb)

The results revealed that the following types are permitted:

- image/jpeg
- image/png
- image/pwg-raster
- image/svg+xml

También se validó manualmente `/image/jpg`


Probamos subiendo una simple imagen `.svg`:
![image](https://github.com/user-attachments/assets/a0d4351e-3548-448d-83ee-c1b4f07d08c7)

Probamos un ataque de `/etc/passwd` disclosure via `File Upload XXE`:
![image](https://github.com/user-attachments/assets/b872540a-f77f-4bab-a719-925907da6522)

Logramos leakear el archivo `upload.php` del backend mediante `XXE` y `PHP Wrappers`:
![image](https://github.com/user-attachments/assets/e6fcca52-d6f0-43b0-aa0c-d61a38dea922)
![image](https://github.com/user-attachments/assets/3668fac6-8c60-4216-8487-80a3c3d494db)


Descubrimos el upload file directory y el cambio de nombre de los archivos subidos:
![image](https://github.com/user-attachments/assets/513c31ff-9e06-4168-a3ed-eda07552aaaa)


Intento subir un script `php` simple conservando los `magic bytes` de una imagen `png`:
![image](https://github.com/user-attachments/assets/6a281d7c-27d9-45c6-b412-b8823d12d98f)

La whitelist permite sólo formatos `jpg` o `png`:
![image](https://github.com/user-attachments/assets/165552fb-ee3b-4196-a21b-af01d0dddd0a)
Blacklist:
![image](https://github.com/user-attachments/assets/f70d9be8-0314-4478-a708-6d51cd1ed8c3)


En el `Intruder` hacemos fuzzing de extensiones con wordlist custom:
![image](https://github.com/user-attachments/assets/e84512ce-7096-4ab3-90cf-38d9f34c7f9d)
![image](https://github.com/user-attachments/assets/8f10fdd7-d03d-4f34-bde9-0f431a2aa4df)

Gracias al código backend, tenemos el directorio de carga y conocemos las operaciones de cambio de nombre en el lado del servidor:
![image](https://github.com/user-attachments/assets/c6877bd7-f069-485f-b50c-d4fdf4d52c2c)

Hacemos fuzzing de nombres de archivos, a la dirección del directorio de carga, con la finalidad de ejecutar los archivos cargados:
![image](https://github.com/user-attachments/assets/d746aac6-1876-485a-9459-2176c800316f)
![image](https://github.com/user-attachments/assets/8e8ef20f-076a-4de6-8456-63bdd4bdfcaf)


Ahora ejecutamos una web shell para resolver el laboratorio, enviamos la `phpbash`:
![image](https://github.com/user-attachments/assets/08b52e53-f0b5-4931-800c-a95d61283c1d)

Ejecutamos la `web-shell` en el browser:
![image](https://github.com/user-attachments/assets/de8d2c90-cbf6-4c1c-b214-deeb440144a7)










