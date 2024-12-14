# Client-side Validation

Try to bypass the client-side file type validations in the above exercise, then upload a web shell to read /flag.txt (try both bypass methods for better practice)

`Hint`: Try to locate the function responsible for validating the input type, then try to remove it without breaking the upload functionality

---

## Attempt to Upload `basic_shell.php`  

When trying to upload our `basic_shell.php`, we received the message **"only images are allowed"**:  

![image](https://github.com/user-attachments/assets/52f7fdb7-b64c-475c-9406-a8cb71966773)  

### Client-Side Validation  

We noticed that the file extension validation is performed on the client side:  
![image](https://github.com/user-attachments/assets/764a21f9-abd3-45d7-8559-2d3793e38af7)


1. The `accept` attribute limits the types of files that can be selected through the file system.  
   - This can easily be bypassed by selecting "All Files."  

   ![image](https://github.com/user-attachments/assets/c7c7cd77-0b14-482c-80c8-b42bc1f7c609)  

2. The `validate()` function performs additional validation.  

By inspecting the source code, we found the actual implementation of this function:  

![image](https://github.com/user-attachments/assets/1de8e730-a295-4f7a-95a9-7e1a9cfdde6a)  

The script uses `upload.php` to handle file uploads, but we cannot directly access this file. However, we found the upload directory `/profile_images/test.php`.  
Additionally, it has a conditional with the `validate()` function, that verifies the file extension.  

### Examining `script.js`  

We accessed the `script.js` file, which contains all the functions used in the frontend:  

![image](https://github.com/user-attachments/assets/600f7a67-0d0a-483e-8e07-4e11836d9e3d)  

In this script, we located the function responsible for validating file extensions, restricting uploads to `jpg`, `jpeg`, or `png`.  

### Two Options to Bypass the Validation  

1. **Bypass the Frontend Filter Using `Burp Suite`**  
   - Upload a valid image (e.g., `.png`) and intercept the request using Burp Suite.  
   - Modify the request payload to include a test PHP script.  

2. **Modify the Frontend Code**  
   - Disable the `validate()` function client-side to bypass the extension check.  

---

## Bypassing the Backend Filter Using `Burp Suite`  

1. Upload a `.png` file.  
2. Intercept the request using Burp Suite and modify the payload to include PHP test code:  

   ![image](https://github.com/user-attachments/assets/a0ff3157-782f-4438-99a5-58df6d96ac46)  
   ![image](https://github.com/user-attachments/assets/8c3728d4-4d09-4762-8f47-ba9fca626ca5)  

3. Confirm the presence of RCE (Remote Code Execution).  
4. Upload a web shell to retrieve the flag:  

   ![image](https://github.com/user-attachments/assets/e04aea65-6e77-4929-b2ec-6fabd8911930)  
   ![image](https://github.com/user-attachments/assets/d0dbfb23-9d27-41cf-95a9-f4276045aee0)  
   ![image](https://github.com/user-attachments/assets/28ff74c7-5384-47ee-bed2-022f125a5e95)  

---

## Modifying the Frontend Code  

1. Locate the `validate()` function in `script.js`:  

   ![image](https://github.com/user-attachments/assets/f63290c8-04d5-40f5-b0eb-26484888590e)  

2. Remove the `validate()` function and its conditional to enable uploads without restrictions.  

   ![image](https://github.com/user-attachments/assets/450597c9-6f26-4731-98c9-0d1eedf396c6)  

3. Upload the `basic_shell.php` file successfully:  

   ![image](https://github.com/user-attachments/assets/5c25caf6-1337-4e29-991e-178ee4cd0d79)  

4. Access the web shell via a browser and resolve the lab:  

   ![image](https://github.com/user-attachments/assets/31e1d577-1e1c-46d5-bb9c-7266a4e9f362)  









