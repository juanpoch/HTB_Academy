# Absent Validation

Try to upload a PHP script that executes the (hostname) command on the back-end server, and submit the first word of it as the answer.

`Hint`: You may use the 'system()' PHP function to execute system commands.

---

## File Upload Functionality Analysis  

When accessing the site, we observe a file upload functionality.  
Using the `Wappalyzer` extension, we can identify that the backend language used is `PHP`:  

![image](https://github.com/user-attachments/assets/26d61a19-e8fc-4db9-8ca5-9f7f8296a57c)  

To test this functionality, we created a simple script named `test.php`:

```php
<?php echo "Hello HTB";?>
```

## Successful File Upload  

We were able to upload the file to the server successfully:  

![image](https://github.com/user-attachments/assets/30647523-b1a7-429e-bf83-657431fe1707)  

After clicking on `Download File`, we observed both the upload directory and the executed script:  

![image](https://github.com/user-attachments/assets/5ab4559d-ee9b-406f-896b-d0ee75562f6c)  

To execute the `hostname` command using `PHP`, we used the following payload:  

```php
<?php system(hostname); ?>
```
## Sending the Request via `Burp Suite`  

We sent the request using `Burp Suite Repeater`:  

![image](https://github.com/user-attachments/assets/51c2a627-3429-4b4f-b113-c08fcb7af03b)  

We then executed the command:  

![image](https://github.com/user-attachments/assets/daf8b721-dc43-442b-be90-fb6ae68fda16)  

Finally, we uploaded the result and successfully completed the lab.  







