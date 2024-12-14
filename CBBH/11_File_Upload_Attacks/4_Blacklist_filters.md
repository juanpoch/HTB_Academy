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

Test payload:
```php
<?php echo "Hello HTB"; ?>
```

# Bypassing File Upload Restrictions and Exploiting `.phar` Uploads

## Attempting to Upload `simple_shell.php`

We tried uploading our `simple_shell.php` file, but we received the following message:  
**`Extension not allowed`**:  
![image](https://github.com/user-attachments/assets/5ab1a8d7-8ab1-456c-8871-187787b109a9)

---

## Bypassing Extension Filtering via Fuzzing

Since we know the backend server validates file extensions using a **blacklist**, we sent the upload request to **Intruder** to perform fuzzing on PHP file extensions:  
![image](https://github.com/user-attachments/assets/978b6062-4a3f-474a-b69c-80752d5626dd)

We used a wordlist containing different alternative extensions for PHP files and observed the responses:  
![image](https://github.com/user-attachments/assets/9baf9d38-b358-405e-bce4-6b744e128aed)

> **Note:**  
> Disable **URL-encode** when fuzzing:  
> ![image](https://github.com/user-attachments/assets/ab4e5b4b-8789-404a-aa96-d70dd56c93c6)

---

## Fuzzing the Uploaded Files

After fuzzing for acceptable PHP extensions, we sent another request to **Intruder** to list the uploaded files and fuzz their extensions as well:  
![image](https://github.com/user-attachments/assets/289c24ab-7736-42b1-bc3b-a252bc01db98)

---

## Successful Bypass Using `.phar`

We discovered that the `.phar` extension not only bypassed the backend's file extension validation but was also executable on the server.

---

## Exploiting the Upload with a Web-Shell

Using **Repeater**, we sent a basic web shell with the `.phar` extension and confirmed that it was uploaded and executed successfully:  
![image](https://github.com/user-attachments/assets/2df96831-5fef-44c9-ba63-c002d543ac9a)

---

## Retrieving the Flag

Finally, we used the uploaded web shell to gain access to the system and retrieve the lab's flag:  
![image](https://github.com/user-attachments/assets/c3dac860-4261-4135-8960-70378b9a9a25)  
![image](https://github.com/user-attachments/assets/fb590d39-028f-4b89-9f80-7f8fe5be6a6b)







