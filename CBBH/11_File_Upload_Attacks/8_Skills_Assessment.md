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

