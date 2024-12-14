# Whitelist Filters

The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions.
Try to bypass both to upload a PHP script and execute code to read "/flag.txt"

`Hint`: You may use either of the last two techniques. If one extension is blocked, try another one that can execute PHP code.

---
Test payload:
```php
<?php echo "Hello HTB"; ?>
```
