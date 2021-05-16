# Strong password

This was a very easy challenge. As the zip is using ordinary ZIP encryption rather than PKZIP, I can just run the following commands to crack the password:
```
zip2john strong_password.zip > hash
john --format=ZIP-opencl --wordlist=~/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Using `rockyou.txt` was a given for the initial try at decryption because ZIP decryption is fast, and while `rockyou.txt` is big enough to have the 14 million most common passwords, it is also small enough to be gone through pretty quickly.

One thing to note, the password was a complicated one that happened to be in `rockyou.txt`. Without `rockyou.txt` this would have taken a lot longer.
