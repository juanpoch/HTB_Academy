# Whitelist Filters

The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions.
Try to bypass both to upload a PHP script and execute code to read "/flag.txt"

`Hint`: You may use either of the last two techniques. If one extension is blocked, try another one that can execute PHP code.

---
Test payload:
```php
<?php echo "Hello HTB"; ?>
```
- Fuzzing extension whitelist: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
(It could be useful to add common image extensions).
- Fuzzing extension list: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst

We attempted to subbmit a simple php script with a test payload:
![image](https://github.com/user-attachments/assets/4b62872a-8a53-4aac-9036-b926dc29415f)
![image](https://github.com/user-attachments/assets/f7bb5a8e-dba6-40ea-a7fb-c57bbb2b6794)

We notice we have differente message responses depending the payload.

We attempted to subbmit a php script using `Double Extensions`:
![image](https://github.com/user-attachments/assets/8e7ab974-0a12-4f57-a81a-db475e750feb)

We attempted to subbmit a php script using a `Reverse Double Extension`:
![image](https://github.com/user-attachments/assets/5d3f324d-9e0e-4878-bd7a-287f780761c0)

We also attempted:
![image](https://github.com/user-attachments/assets/35526498-6f80-4f59-a5c0-771c6e74ef93)
![image](https://github.com/user-attachments/assets/95bad4f1-b219-43ba-a443-a6adee0fd057)
![image](https://github.com/user-attachments/assets/f69b6ed7-1468-47c2-bb00-77c6168d40d2)


We tried to submit a php script with null bytes:
![image](https://github.com/user-attachments/assets/977014b2-3f26-4001-a57b-dd64e0114667)

We perform a common extension fuzzing with `Burp Suite Intruder` in order to know the extensions whitelisted:
![image](https://github.com/user-attachments/assets/05fb203f-bed3-498d-a3b9-4ae4ef6b6489)
all of this extensios are not allowed.

We performed a extension fuzzing using `Burp Suite Intruder`:
![image](https://github.com/user-attachments/assets/e3d26584-e313-4a44-870c-54af813e562e)

![image](https://github.com/user-attachments/assets/78f9a8d2-ed7e-478d-a687-e36d024344b5)







