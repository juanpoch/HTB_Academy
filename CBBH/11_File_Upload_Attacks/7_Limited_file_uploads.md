# Limited File Uploads

- The above exercise contains an upload functionality that should be secure against arbitrary file uploads.
 Try to exploit it using one of the attacks shown in this section to read "/flag.txt"

  `Hint`: Use an attack that can read files, and don't forget to check the page source!
- Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes)
  
  `Hint`: Use a different payload to read source code.
---
  
XSS via comment injection:
```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
```
