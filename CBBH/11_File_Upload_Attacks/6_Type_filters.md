# Type Filters
<br>
 The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. 
 Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt"

 `Hint`: Start with a request that can be uploaded (e.g. jpg image), then try to find an allowed PHP extension that doesn't get blocked,
 then utilize one of the whitelist filter bypasses to bypass both extension filters.

 ---
- Test payload:
  ```php
  <?php echo "Hello HTB"; ?>
  ```
- Basic web shell:
  ```php
  <?php system($_REQUEST['cmd']); ?>
  ```
 - Web-all-content-types wordlist: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt

- Descargamos la wordlist y filtramos sólo por content-type relacionados a imágenes:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```
Nota: `/image/jpg` no está en la lista.

- Common mime types:
  - `jpeg`: `FF D8 FF`
  - `gif`: `GIF8` (GIF87a | GIF89a)

  <br>

 ---
<br>

## Ejercicio

Hacemos fuzzing de `Content-Type` header para ver qué tipos son permitidos:
![image](https://github.com/user-attachments/assets/b6376c4b-05d7-4821-80c6-04b0901559b9)

![image](https://github.com/user-attachments/assets/287f8443-d7fc-41c0-93af-7140125607ca)

Tenemos que sólo son permitidos los siguientes tipos:
- image/gif
- image/jpeg
- image/png


De forma manual sabemos que también permite `image/jpg`.


Ahora testeamos el `file content` utilizando `magic bytes` para conocer los `MIME Types` permitidos:
![image](https://github.com/user-attachments/assets/b5d9d02b-5984-48b1-9473-bfd797379b27)
![image](https://github.com/user-attachments/assets/8acbe838-c50e-48ac-8322-5a2948e611ff)



Intentamos subir la web shell con la extensión `.php` y el servidor nos responde `Extension not allowed`:
![image](https://github.com/user-attachments/assets/290960dc-0829-456a-a84f-2c4ece59ded5)

Sabemos que tenemos blacklist and whitelist. Hacemos fuzzing de whitelist con common web extensions de Seclists, para investigar si se permite alguna extensión además de las extensiones de imágenes:
![image](https://github.com/user-attachments/assets/c1bb7c02-26fc-47f6-a32c-0a0d3bf25942)
![image](https://github.com/user-attachments/assets/05e266e9-ec3a-4658-a82a-47d273a079e2)
No hay ninguna extensión web adicional que esté incluida en la whitelist.
Sabemos que el servidor está validando extensiones a través de una blacklist, que contiene bastantes tipos de extension `.php`, en este caso, el servidor contesta con el mensaje `Extension not allowed`.
Cuando la validación se realiza a través de la whitelist, el servidor responde `Only images are allowed`.

