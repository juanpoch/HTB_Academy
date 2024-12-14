# Blacklist Filters

Try to find an extension that is not blacklisted and can execute `PHP` code on the web server, and use it to read `/flag.txt`.

`Hint`: When you fuzz for allowed extensions, change the content to a PHP 'hello world' script. 
Then, when you you check the uploaded file, you would know whether it can execute PHP code.

---

Usefull list extensions:
- `.NET`: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP
- `PHP`: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst
- `Common Web Extensions`: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
---

Payload de prueba:
```php
<?php echo "Hello HTB"; ?>
```

Intentamos subir nuestra `simple_shell.php` pero recibimos un mensaje `Extension not allowed`:
![image](https://github.com/user-attachments/assets/5ab1a8d7-8ab1-456c-8871-187787b109a9)

Ya que sabemos que el servidor backend está validando extensiones a través de una blacklist, enviamos la request al `Inrtuder` para hacer fuzzing de extensiones `PHP`:
![image](https://github.com/user-attachments/assets/978b6062-4a3f-474a-b69c-80752d5626dd)

![image](https://github.com/user-attachments/assets/9baf9d38-b358-405e-bce4-6b744e128aed)

Luego, enviamos al intruder la request para visualizar los archivos cargados, hacemos fuzzing de extensiones también:
![image](https://github.com/user-attachments/assets/289c24ab-7736-42b1-bc3b-a252bc01db98)

Vemos que la extensión `.phar` no sólo pudo dubirse al servidor correctamente, sino que, es la única de las subidas, que tiene capacidad de ejecutar código.

En el repeater, enviamos una web-shell básica con extensión `.phar`:
![image](https://github.com/user-attachments/assets/2df96831-5fef-44c9-ba63-c002d543ac9a)

Conseguimos la flag y resolvemos el lab:
![image](https://github.com/user-attachments/assets/c3dac860-4261-4135-8960-70378b9a9a25)

![image](https://github.com/user-attachments/assets/fb590d39-028f-4b89-9f80-7f8fe5be6a6b)






