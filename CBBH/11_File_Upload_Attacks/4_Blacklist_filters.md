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
