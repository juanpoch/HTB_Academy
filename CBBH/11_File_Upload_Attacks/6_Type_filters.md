# Type Filters

 The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. 
 Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt"

 `Hint`: Start with a request that can be uploaded (e.g. jpg image), then try to find an allowed PHP extension that doesn't get blocked,
 then utilize one of the whitelist filter bypasses to bypass both extension filters.

 ---

 - Web-all-content-types wordlist: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt

- Descargamos la wordlist y filtramos sólo por content-type relacionados a imágenes:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```
Nota: `/image/jpg` no está en la lista.

- Common mime types:
  - `jpeg`: `FF D8 FF`
  - `gif`: `GIF8`

  <br>

 ---

<br>
Hacemos fuzzing de `Content-Type` header para ver qué tipos son permitidos:
![image](https://github.com/user-attachments/assets/b6376c4b-05d7-4821-80c6-04b0901559b9)

![image](https://github.com/user-attachments/assets/287f8443-d7fc-41c0-93af-7140125607ca)

Tenemos que sólo son permitidos los siguientes tipos:
- image/gif
- image/jpeg
- image/png
De forma manual sabemos que también permite `image/jpg`.

